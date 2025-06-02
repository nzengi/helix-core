use flate2::{Compress, Decompress, Compression as FlateCompression};

pub struct HelixCompression {
    level: u32,
}

impl HelixCompression {
    pub fn new() -> Self {
        Self {
            level: 6,
        }
    }
    
    pub fn set_level(&mut self, level: u32) {
        self.level = level.min(9);
    }
    
    pub fn compress(&self, data: &[u8]) -> Vec<u8> {
        let mut compress = Compress::new(FlateCompression::new(self.level), false);
        let mut output = Vec::with_capacity(data.len());
        
        compress.compress_vec(data, &mut output, flate2::FlushCompress::Finish).unwrap();
        output
    }
    
    pub fn decompress(&self, data: &[u8]) -> Vec<u8> {
        let mut decompress = Decompress::new(false);
        let mut output = Vec::with_capacity(data.len() * 2);
        
        decompress.decompress_vec(data, &mut output, flate2::FlushDecompress::Finish).unwrap();
        output
    }
}

pub fn dlc_compress(data: &[u8]) -> Vec<u8> {
    let mut compressor = HelixCompression::new();
    compressor.set_level(9);
    compressor.compress(data)
}