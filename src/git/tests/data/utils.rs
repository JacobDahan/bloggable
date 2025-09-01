mod utils {
    pub fn print_with_timestamp(message: &str) -> String {
        format!("{} - {}", chrono::Utc::now(), message)
    }
}
