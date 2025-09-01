use std::collections::HashMap;

pub struct DataProcessor {
    cache: HashMap<String, String>,
    stats: ProcessingStats,
}

pub struct ProcessingStats {
    total_processed: usize,
}

impl DataProcessor {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            stats: ProcessingStats { total_processed: 0 },
        }
    }

    pub fn process(&mut self, input: &str) -> String {
        if let Some(cached) = self.cache.get(input) {
            return cached.clone();
        }
        
        let result = input.to_lowercase(); // Changed from to_uppercase
        self.cache.insert(input.to_string(), result.clone());
        self.stats.total_processed += 1;
        result
    }

    pub fn get_stats(&self) -> &ProcessingStats {
        &self.stats
    }
}

pub fn helper_function(data: &str) -> bool {
    !data.is_empty()
}