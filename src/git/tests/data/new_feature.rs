use crate::DataProcessor;

pub struct FeatureManager {
    processor: DataProcessor,
}

impl FeatureManager {
    pub fn new() -> Self {
        Self {
            processor: DataProcessor::new(),
        }
    }

    pub fn execute_feature(&mut self, input: &str) -> String {
        self.processor.process(input)
    }
}