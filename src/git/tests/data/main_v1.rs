use std::collections::HashMap;

pub struct DataProcessor {
    cache: HashMap<String, String>,
}

impl DataProcessor {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn process(&mut self, input: &str) -> String {
        if let Some(cached) = self.cache.get(input) {
            return cached.clone();
        }
        
        let result = input.to_uppercase();
        self.cache.insert(input.to_string(), result.clone());
        result
    }
}

pub fn helper_function(data: &str) -> bool {
    !data.is_empty()
}