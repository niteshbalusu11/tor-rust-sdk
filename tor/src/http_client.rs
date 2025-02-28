// src/http_client.rs - Revised for proper timeouts with synchronous read/write
use crate::{ensure_runtime, TorErrors};
use log::debug;
use serde::{Deserialize, Serialize};
use socks::Socks5Stream;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Supported HTTP methods
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
}

/// HTTP response structure compatible with FFI
#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub body: String,
    pub error: Option<String>,
}

/// HTTP request parameters
#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct HttpRequestParams {
    pub url: String,
    pub method: HttpMethod,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub timeout_ms: Option<u64>,
}

/// Makes an HTTP request through the Tor SOCKS proxy
pub fn make_http_request(
    params: HttpRequestParams,
    socks_proxy: String,
) -> Result<HttpResponse, TorErrors> {
    // Parse the URL to get host, port, and path
    let parsed_url = match url::Url::parse(&params.url) {
        Ok(u) => u,
        Err(e) => {
            return Ok(HttpResponse {
                status_code: 0,
                body: String::new(),
                error: Some(format!("Invalid URL: {}", e)),
            });
        }
    };

    // Extract values from the URL before moving into the async block
    let host = parsed_url.host_str().unwrap_or("localhost").to_string();
    let port = parsed_url
        .port()
        .unwrap_or(if parsed_url.scheme() == "https" {
            443
        } else {
            80
        });
    let scheme = parsed_url.scheme().to_string();
    let path = parsed_url.path().to_string();
    let query = parsed_url.query().unwrap_or("").to_string();

    // Determine if we're using HTTPS
    let is_https = scheme == "https";

    // Get timeout duration
    let timeout_ms = params.timeout_ms.unwrap_or(30000);
    debug!("Using timeout of {} ms", timeout_ms);

    // Run in Tokio runtime with an overall timeout
    let result = ensure_runtime().lock().unwrap().block_on(async move {
        // Apply timeout to the entire operation
        match timeout(Duration::from_millis(timeout_ms), async {
            debug!("Starting HTTP request to {}", params.url);

            // Set up timeout monitoring
            let start_time = Instant::now();
            let deadline = start_time + Duration::from_millis(timeout_ms);

            // Create custom timeout error
            let timeout_error = || TorErrors::TcpStreamError("Operation timed out".to_string());

            // Function to check if operation has timed out
            let has_timed_out = move || Instant::now() >= deadline;

            // Connect to SOCKS proxy
            let target = format!("{}:{}", host, port);
            debug!("Connecting to {} via SOCKS proxy {}", target, socks_proxy);

            // We must use a spawn_blocking here since Socks5Stream::connect is synchronous
            // and could block the tokio runtime
            let socks_stream = tokio::task::spawn_blocking(move || {
                // Set socket options with timeout
                let stream = Socks5Stream::connect(socks_proxy.as_str(), target.as_str())?;
                stream.get_ref().set_read_timeout(Some(Duration::from_millis(5000)))?;
                stream.get_ref().set_write_timeout(Some(Duration::from_millis(5000)))?;
                Ok::<Socks5Stream, std::io::Error>(stream)
            })
            .await
            .map_err(|e| TorErrors::ThreadingError(e))?
            .map_err(|e| TorErrors::IoError(e))?;

            debug!("Connected to SOCKS proxy");

            // For HTTPS we would need to establish a TLS connection here
            if is_https {
                return Err(TorErrors::TcpStreamError(
                    "HTTPS not implemented in this basic version".to_string(),
                ));
            }

            // Handle building and sending the request in a blocking task
            let method_str = match params.method {
                HttpMethod::GET => "GET",
                HttpMethod::POST => "POST",
                HttpMethod::PUT => "PUT",
                HttpMethod::DELETE => "DELETE",
                HttpMethod::HEAD => "HEAD",
                HttpMethod::OPTIONS => "OPTIONS",
            };

            let full_path = if query.is_empty() {
                path.clone()
            } else {
                format!("{}?{}", path, query)
            };

            // Create the request string
            let mut request = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
                method_str, full_path, host
            );

            // Add headers if provided
            if let Some(headers) = &params.headers {
                for (key, value) in headers {
                    request.push_str(&format!("{}: {}\r\n", key, value));
                }
            }

            // Add Content-Length if body is provided
            if let Some(body) = &params.body {
                request.push_str(&format!("Content-Length: {}\r\n", body.len()));
            }

            // End headers section
            request.push_str("\r\n");

            // Add body if provided
            if let Some(body) = &params.body {
                request.push_str(body);
            }

            let response = tokio::task::spawn_blocking(move || {
                if has_timed_out() {
                    return Err(timeout_error());
                }

                let mut stream = socks_stream;
                debug!("Sending request: {} {}", method_str, full_path);

                // Write request to socket
                stream.write_all(request.as_bytes())
                    .map_err(|e| TorErrors::IoError(e))?;
                stream.flush()
                    .map_err(|e| TorErrors::IoError(e))?;

                // Read response
                let mut response = Vec::new();
                let mut buffer = [0; 4096];

                debug!("Reading response...");

                while !has_timed_out() {
                    match stream.read(&mut buffer) {
                        Ok(0) => break, // Connection closed
                        Ok(n) => {
                            response.extend_from_slice(&buffer[0..n]);

                            // Check if we've received the complete response
                            // This is a simple heuristic that might not work for all responses
                            let response_str = String::from_utf8_lossy(&response);

                            if let Some(headers_end) = response_str.find("\r\n\r\n") {
                                // Check if we have Content-Length
                                if let Some(cl_line) = response_str
                                    .lines()
                                    .find(|line| line.to_lowercase().starts_with("content-length:"))
                                {
                                    if let Some(cl_str) = cl_line.split(':').nth(1) {
                                        if let Ok(cl) = cl_str.trim().parse::<usize>() {
                                            let body_received = response.len() - (headers_end + 4);
                                            if body_received >= cl {
                                                debug!("Received complete response with Content-Length: {}", cl);
                                                break;
                                            }
                                        }
                                    }
                                } else if response_str.contains("Transfer-Encoding: chunked") {
                                    // Simple check for end of chunked encoding
                                    if response_str.ends_with("\r\n0\r\n\r\n") {
                                        debug!("Received complete chunked response");
                                        break;
                                    }
                                }
                                // If no Content-Length or chunked encoding, rely on connection close
                            }
                        }
                        Err(e) => {
                            // Socket read timeout or error
                            if e.kind() == std::io::ErrorKind::WouldBlock ||
                               e.kind() == std::io::ErrorKind::TimedOut {
                                // If headers are complete and we have some body, consider it done
                                if response.len() > 0 &&
                                   String::from_utf8_lossy(&response).contains("\r\n\r\n") {
                                    debug!("Read timed out, but we have headers and some body");
                                    break;
                                }

                                if has_timed_out() {
                                    debug!("Overall timeout reached while reading");
                                    break;
                                }

                                // Otherwise continue trying to read
                                continue;
                            }

                            return Err(TorErrors::IoError(e));
                        }
                    }
                }

                if has_timed_out() && response.is_empty() {
                    return Err(timeout_error());
                }

                debug!("Response read complete, size: {} bytes", response.len());

                // Parse the response
                let response_str = String::from_utf8_lossy(&response).to_string();

                // Extract status code (basic parsing)
                let status_code =
                    if response_str.starts_with("HTTP/1.1 ") || response_str.starts_with("HTTP/1.0 ") {
                        let status_line = response_str.lines().next().unwrap_or("");
                        let parts: Vec<&str> = status_line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            parts[1].parse::<u16>().unwrap_or(0)
                        } else {
                            0
                        }
                    } else {
                        0
                    };

                // Extract body (basic parsing)
                let body = if let Some(pos) = response_str.find("\r\n\r\n") {
                    response_str[pos + 4..].to_string()
                } else {
                    "".to_string()
                };

                debug!("Parsed HTTP response with status code: {}", status_code);

                Ok(HttpResponse {
                    status_code,
                    body,
                    error: None,
                })
            })
            .await
            .map_err(|e| TorErrors::ThreadingError(e))??;

            Ok(response)
        })
        .await {
            Ok(result) => result,
            Err(_) => {
                debug!("Request timed out after {} ms", timeout_ms);
                Ok(HttpResponse {
                    status_code: 0,
                    body: String::new(),
                    error: Some(format!("Request timed out after {} ms", timeout_ms)),
                })
            }
        }
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TorService, TorServiceParam};
    use serial_test::serial;
    use std::convert::TryInto;

    #[test]
    #[serial(tor)]
    fn test_http_request() {
        // Start Tor service
        let service: TorService = TorServiceParam {
            socks_port: Some(19054),
            data_dir: String::from("/tmp/sifir_rs_sdk/"),
            bootstrap_timeout_ms: Some(45000),
        }
        .try_into()
        .unwrap();

        let mut owned_node = service.into_owned_node().unwrap();

        // Make a simple HTTP GET request
        let params = HttpRequestParams {
            url: "http://example.com".to_string(),
            method: HttpMethod::GET,
            headers: None,
            body: None,
            timeout_ms: Some(10000), // 10 seconds
        };

        let response = make_http_request(params, "127.0.0.1:19054".to_string()).unwrap();

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("Example Domain"));
        assert!(response.error.is_none());

        owned_node.shutdown().unwrap();
    }
}
