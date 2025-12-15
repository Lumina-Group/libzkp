use crate::utils::error_handling::{ZkpError, ZkpResult};
use rand::Rng;

/// Temporal Visual Code Signal Processing Simulation
///
/// This module simulates the encoding of (s, t) into a temporal waveform
/// and the decoding of that waveform back into (s, t).
///
/// In a real implementation, this would involve computer vision and signal processing.
/// Here, we simulate the transmission channel with noise.

#[derive(Clone, Debug)]
pub struct TemporalCode {
    pub s: u64, // Secret value (random nonce)
    pub t: u64, // Time slot
}

#[derive(Clone, Debug)]
pub struct Waveform {
    pub frames: Vec<f32>, // Simulated brightness values (0.0 to 1.0)
    pub fps: u32,
}

impl TemporalCode {
    pub fn new(s: u64, t: u64) -> Self {
        Self { s, t }
    }

    /// Encode the (s, t) payload into a simulated waveform
    /// We use a simple bit-stream encoding with a sync header
    pub fn encode(&self, fps: u32) -> Waveform {
        let mut rng = rand::thread_rng();
        let mut frames = Vec::new();
        
        // Sync header: High, Low, High, High (just a pattern)
        frames.push(1.0);
        frames.push(0.0);
        frames.push(1.0);
        frames.push(1.0);

        // Serialize data: s (64 bits) + t (64 bits)
        let data = ((self.s as u128) << 64) | (self.t as u128);
        
        for i in (0..128).rev() {
            let bit = (data >> i) & 1;
            // Add noise/jitter to the signal
            let base_val = if bit == 1 { 0.8 } else { 0.2 };
            let noise: f32 = rng.gen_range(-0.05..0.05);
            frames.push(base_val + noise);
        }

        Waveform { frames, fps }
    }
}

impl Waveform {
    /// Decode the waveform back into (s, t)
    /// This simulates the receiver processing the video feed
    pub fn decode(&self) -> ZkpResult<TemporalCode> {
        // Skip sync header (4 frames)
        if self.frames.len() < 4 + 128 {
             return Err(ZkpError::InvalidInput("Waveform too short".to_string()));
        }
        
        // Simple thresholding
        let threshold = 0.5;
        let mut data: u128 = 0;

        for (i, &val) in self.frames.iter().skip(4).take(128).enumerate() {
            let bit = if val > threshold { 1 } else { 0 };
            data = (data << 1) | bit;
        }

        let t = (data & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        let s = (data >> 64) as u64;

        Ok(TemporalCode { s, t })
    }
}
