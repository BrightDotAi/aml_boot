use std::{time::Duration, path::PathBuf};

use crate::protocol::Handle;

// IN is device to host
const ADNL_IN_EP: u8 = 0x81;
// OUT is host to device
const ADNL_OUT_EP: u8 = 0x01;


enum Cmd_Adnl {
  Devices,
  /// Partition num, offset, length
  OemMreadInit(u8, u64, u64),
  OemMreadRequest,
  OemMreadUpload,
  OemMreadFinish,

  /// Partition num, offset, length
  OemMwriteInit(u8, u64, u64),
  OemMwriteRequest,

}


impl From<Cmd_Adnl> for String {
  fn from(value: Cmd_Adnl) -> Self {
      match value {
        Cmd_Adnl::Devices => "getvar:downloadsize".into(),
        Cmd_Adnl::OemMreadInit(part, offset, len) => format!("oem mread {len} normal mmc {part} {offset}"),
        Cmd_Adnl::OemMreadRequest => "mread:status=request".into(),
        Cmd_Adnl::OemMreadUpload => "mread:status=upload".into(),
        Cmd_Adnl::OemMreadFinish => "mread:status=finish".into(),

        Cmd_Adnl::OemMwriteInit(part, offset, len) => format!("oem mwrite {len} normal mmc {part} {offset}"),
        Cmd_Adnl::OemMwriteRequest => "mwrite".into(),
      }
  }
}

pub fn oem_mwrite(h: &Handle, offset: u64, file: impl AsRef<str>) {

  if let Some(data) = std::fs::read(PathBuf::from(file.as_ref())).ok() {
    println!("File is {} Bytes", data.len());

    // let len = data.len() as u64;
    let mut offset = offset;
    let timeout = Duration::from_millis(3000);
    let mut total = 0;
    let mut ix = 0;
    let mut last_pcent = 0.0;
    for ch in data.chunks(0x20000) {

      if let Ok(len) = h.write_bulk(ADNL_OUT_EP, String::from(Cmd_Adnl::OemMwriteInit(1, offset, ch.len() as u64)).as_bytes(), timeout) {
        // println!("Wrote {len} bytes!");

      } else {
        println!("Failed to write");
        return
      }
      let mut resp = [0u8; 512];
      match h.read_bulk(ADNL_IN_EP, &mut resp, timeout) {
        Ok(len) => {
          // println!("Read {len} bytes!");
          // println!("{}", String::from_utf8_lossy(&resp));
        }
        Err(e) => {
          println!("Failed to read: {:?}", e);
          return
        }
      }
      h.write_bulk(ADNL_OUT_EP, String::from(Cmd_Adnl::OemMwriteRequest).as_bytes(), timeout).ok();
      h.read_bulk(ADNL_IN_EP, &mut resp, timeout).ok();
      // println!("{}", String::from_utf8_lossy(&resp));
      // for ch in data.chunks(512) {
        resp = [0u8; 512];
        match  h.write_bulk(ADNL_OUT_EP, &data[(ix*ch.len())..((ix+1) * ch.len())], timeout) {
          Ok(by) => {
            total += by;
            let pcent = ((total as f64 /  data.len() as f64) * 100.0).round();
            if pcent != last_pcent {
              println!("Percent complete: {:02}%", pcent);
              last_pcent = pcent.round();
            }
          }
          Err(e) => {
            println!("Failed to write bytes: {:?}", e);
          }
        }
        h.read_bulk(ADNL_IN_EP, &mut resp, timeout).ok();
        // println!("{}", String::from_utf8_lossy(&resp));
        offset = offset + ch.len() as u64;
        ix += 1;
    }


    // h.write_bulk(ADNL_OUT_EP, String::from(Cmd_Adnl::OemMwriteRequest).as_bytes(), timeout).ok();
    // h.read_bulk(ADNL_IN_EP, &mut resp, timeout).ok();
    // println!("{}", String::from_utf8_lossy(&resp));
    // resp = [0u8; 512];
    // h.write_bulk(ADNL_OUT_EP, &data, timeout).ok();
    // h.read_bulk(ADNL_IN_EP, &mut resp, timeout).ok();
    // println!("{}", String::from_utf8_lossy(&resp));
  }

}


pub fn oem_mread(h: &Handle, offset: u64, len: u64) {

  let len = len;
  let offset = offset;
  let timeout = Duration::from_millis(3000);
  if let Ok(len) = h.write_bulk(ADNL_OUT_EP, String::from(Cmd_Adnl::OemMreadInit(1, offset, len)).as_bytes(), timeout) {
    println!("Wrote {len} bytes!");
  } else {
    println!("Failed to write");
    return
  }
  let mut buf = [0u8; 8192];
  match h.read_bulk(ADNL_IN_EP, &mut buf, timeout) {
    Ok(len) => {
      println!("Read {len} bytes!");
      println!("{}", String::from_utf8_lossy(&buf));
    }
    Err(e) => println!("Failed to read: {:?}", e)
  }
  h.write_bulk(ADNL_OUT_EP, String::from(Cmd_Adnl::OemMreadRequest).as_bytes(), timeout).ok();
  h.read_bulk(ADNL_IN_EP, &mut buf, timeout).ok();
  println!("{}", String::from_utf8_lossy(&buf));

  h.write_bulk(ADNL_OUT_EP, String::from(Cmd_Adnl::OemMreadUpload).as_bytes(), timeout).ok();
  if let Ok(rlen) = h.read_bulk(ADNL_IN_EP, &mut buf, timeout) {
    println!("=== Read {rlen} Bytes ===");
    let mut ix = 0;
    let mut cnt = 0;
    let mut addr = offset;
    while ix < rlen {
      if cnt == 0 {
        print!("{:08x}: ", addr);
        addr += 16;
      }
      let s = format!("{:02x}", buf[ix]);
      print!("{s} ");
      ix += 1;
      cnt += 1;
      if cnt > 15 {
        println!("");
        cnt = 0;
      }
    }
  }
  println!("=== ===");

  // h.write_bulk(ADNL_OUT_EP, String::from(Cmd_Adnl::OemMreadFinish).as_bytes(), timeout).ok();
  // h.read_bulk(ADNL_IN_EP, &mut buf, timeout).ok();
  // println!("{}", buf.len());

}

pub fn devices(h: &Handle) {

  let timeout = Duration::from_millis(3000);
  if let Ok(len) = h.write_bulk(ADNL_OUT_EP, String::from(Cmd_Adnl::Devices).as_bytes(), timeout) {
    println!("Wrote {len} bytes!");
  } else {
    println!("Failed to write");
    return
  }
  let mut buf = [0u8; 512];
  match h.read_bulk(ADNL_IN_EP, &mut buf, timeout) {
    Ok(len) => {
      println!("Read {len} bytes!");
      println!("{}", String::from_utf8_lossy(&buf));
    }
    Err(e) => println!("Failed to read: {:?}", e)
  }
}
