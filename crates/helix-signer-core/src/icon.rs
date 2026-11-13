//! The app icon, drawn in code: a double helix on a dark rounded square.
//! ``png(size)`` renders PNG bytes (the same pixels as the Python signer's
//! ``icon.py``); ``ico(sizes)`` wraps PNG images in a Windows ``.ico``.

const BACKGROUND: [f64; 3] = [11.0, 18.0, 32.0];
const STRANDS: [[f64; 3]; 2] = [[45.0, 212.0, 191.0], [245.0, 158.0, 11.0]];
const RUNG: [f64; 3] = [148.0, 163.0, 184.0];

fn blend(base: [f64; 3], color: [f64; 3], alpha: f64) -> [f64; 3] {
    [base[0] + (color[0] - base[0]) * alpha, base[1] + (color[1] - base[1]) * alpha, base[2] + (color[2] - base[2]) * alpha]
}

/// RGBA rows (each with its PNG filter byte) of the icon.
pub fn pixels(size: u32) -> Vec<Vec<u8>> {
    let size_f = size as f64;
    let scale = size_f / 256.0;
    let radius = 48.0 * scale;
    let amplitude = 54.0 * scale;
    let width = 15.0 * scale;
    let mut rows = Vec::with_capacity(size as usize);
    for y in 0..size {
        let mut row = vec![0u8];
        let fy = y as f64 + 0.5;
        let phase = (fy / size_f) * 2.4 * std::f64::consts::PI + 0.6;
        let centers = [size_f / 2.0 + amplitude * phase.sin(), size_f / 2.0 - amplitude * phase.sin()];
        let depth = phase.cos();
        for x in 0..size {
            let fx = x as f64 + 0.5;
            let dx = (radius - fx).max(0.0).max(fx - (size_f - radius));
            let dy = (radius - fy).max(0.0).max(fy - (size_f - radius));
            let coverage = if dx != 0.0 || dy != 0.0 { (radius - dx.hypot(dy) + 0.5).clamp(0.0, 1.0) } else { 1.0 };
            let mut color = BACKGROUND;
            let rung = (((fy / scale) % 32.0) - 16.0).abs();
            let (low, high) = if centers[0] <= centers[1] { (centers[0], centers[1]) } else { (centers[1], centers[0]) };
            if rung > 13.0 && low < fx && fx < high {
                color = blend(color, RUNG, ((rung - 13.0) / 2.0).min(1.0) * 0.8);
            }
            let order = if depth > 0.0 { [1, 0] } else { [0, 1] };
            for index in order {
                let distance = (fx - centers[index]).abs();
                let alpha = (width / 2.0 - distance + 0.5).clamp(0.0, 1.0);
                if alpha != 0.0 {
                    color = blend(color, STRANDS[index], alpha);
                }
            }
            row.extend_from_slice(&[
                color[0].round_ties_even() as u8,
                color[1].round_ties_even() as u8,
                color[2].round_ties_even() as u8,
                (255.0 * coverage).round_ties_even() as u8,
            ]);
        }
        rows.push(row);
    }
    rows
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for byte in data {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// zlib stream with stored (uncompressed) deflate blocks.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let chunks: Vec<&[u8]> = if data.is_empty() { vec![&[][..]] } else { data.chunks(65535).collect() };
    for (index, chunk) in chunks.iter().enumerate() {
        out.push(if index + 1 == chunks.len() { 1 } else { 0 });
        let length = chunk.len() as u16;
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&(!length).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    let mut body = kind.to_vec();
    body.extend_from_slice(data);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&body).to_be_bytes());
    out
}

/// The icon as PNG bytes.
pub fn png(size: u32) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&size.to_be_bytes());
    header.extend_from_slice(&size.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    let raw: Vec<u8> = pixels(size).concat();
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(chunk(b"IHDR", &header));
    out.extend(chunk(b"IDAT", &zlib_stored(&raw)));
    out.extend(chunk(b"IEND", b""));
    out
}

/// A Windows ``.ico`` with one PNG entry per size.
pub fn ico(sizes: &[u32]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = sizes.iter().map(|size| png(*size)).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (size, image) in sizes.iter().zip(&images) {
        let side = if *size >= 256 { 0 } else { *size as u8 };
        out.extend_from_slice(&[side, side, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(image.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += image.len() as u32;
    }
    for image in images {
        out.extend(image);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_and_ico() {
        let data = png(32);
        assert!(data.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(&data[12..16], b"IHDR");
        assert_eq!(u32::from_be_bytes(data[16..20].try_into().unwrap()), 32);
        let container = ico(&[16, 256]);
        assert_eq!(&container[..6], &[0, 0, 1, 0, 2, 0]);
        assert_eq!(container[6], 16);
        assert_eq!(container[22], 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }
}
