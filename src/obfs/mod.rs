pub struct Obfs {
    init: bool,
}

impl Obfs {
    pub fn new() -> Self {
        Obfs { init: false }
    }
    pub fn obfs_http_request(&mut self) -> String {
        if self.init {
            return "".to_string();
        }
        self.init = true;

        let mut str = format!("{} {} HTTP/1.1\r\n", "GET", "/");
        str += &format!("Host: {}\r\n", "abc.com");
        str += &format!("User-Agent: curl/7.{}.{}\r\n", 1, 14);
        str += &format!("Upgrade: websocket\r\n");
        str += &format!("Connection: Upgrade\r\n");
        str += &format!("Sec-WebSocket-Key: {}\r\n", "abcdef");
        str += &format!("Content-Length: {}\r\n\r\n", 12345);
        return str.to_string();
    }

    pub fn obfs_http_response(&mut self) -> String {
        if self.init {
            return "".to_string();
        }
        self.init = true;

        let mut str = format!("HTTP/1.1 101 Switching Protocols\r\n");
        str += &format!("Server: nginx/1.{}.{}\r\n", 1, 2);
        str += &format!("Date: {}\r\n", "2020-01-12");
        str += &format!("Upgrade: websocket\r\n");
        str += &format!("Connection: Upgrade\r\n");
        str += &format!("Sec-WebSocket-Accept: {}\r\n", "abc");
        str += &format!("\r\n").to_string();
        return str.to_string();
    }
}
