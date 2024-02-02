use std::{time::Duration, path::{Path, PathBuf}, io};
use std::io::Write;

use regex::Regex;

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
              print!("\rPercent complete: {:3}%", pcent);
              io::stdout().flush().ok();
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

    println!("\nFinished!");


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

fn do_read_bulk(h: &Handle) -> Result<String,String> {

  let timeout = Duration::from_millis(3000);
  let mut buf = [0u8; 512];
  let result = match h.read_bulk(ADNL_IN_EP, &mut buf, timeout) {
    Ok(len) => {
      println!("Read {len} bytes!");
      // println!("{:?}", &buf);
      let s = String::from_utf8_lossy(&buf);
      // get the first item as responses are a bit strange from the device (and is probably a bug)
      // OKAY0x3F800<nul>max-download-size<nul>serialno<nul>product<nul>AMLOGIC<nul>identify<nul>getc
      if let Some(r) = s.split('\0').into_iter().next() {
        // println!("{:?}",r);
        let re = Regex::new(r"(?<status>(OKAY|FAIL|DATA))(?<msg>.*)").unwrap();
        match re.captures(r) {
          Some(cap) => {
            match &cap["status"] {
              "OKAY"|"DATA" => {
                Ok(String::from(&cap["msg"]))
              }
              "FAIL" => {
                Err(String::from(&cap["msg"]))
              }
              _ => {
                Err("Unknown response".into())
              }
            }
            // dlsize = u32::from_str_radix((&cap["size"]).to_string().to_lowercase().replace("0x","").as_str(),16).unwrap();
          }
          None => {
            println!("Failed to find expected response: '{r}'!");
            Err("Bad News Bears".into())
            // return
          }
        }
        // println!("Download size {:08X}", dlsize);
      } else {
        println!("Failed to get expected response: '{}'", s);
        Err("Bad News Bears".into())
        // return
      }
    }
    Err(e) => {
      println!("Failed to read: {:?}", e);
      Err("Failed to read".into())
    }
  };
  result
}


fn do_write_blk_cmd(h: &Handle, cmd: impl AsRef<str>) -> Result<usize, String> {

  let timeout = Duration::from_millis(3000);
  let by = cmd.as_ref().as_bytes();
  println!("Sending command: '{}'", cmd.as_ref());
  h.write_bulk(ADNL_OUT_EP, by, timeout).map_err(|e| {
    println!("Failed to send command '{}' : {}", cmd.as_ref(), e);
    "Failed to send command".to_string()
  })
}


pub fn do_flash(h: &Handle, bl1: impl AsRef<str>, bl2: impl AsRef<str>, wic: impl AsRef<str>) {

  let data = if let Ok(data) = std::fs::read(PathBuf::from(bl1.as_ref())) {
    data
  } else {
    println!("Error: Failed to read {}", bl1.as_ref());
    return
  };

  if let Ok(data) = std::fs::read(PathBuf::from(bl2.as_ref())) {

  } else {
    println!("Error: Failed to read {}", bl1.as_ref());
    return
  }

  let timeout = Duration::from_millis(3000);
  let mut buf = [0u8; 512];

  // println!("Flushing buffer");
  // h.write_bulk(ADNL_OUT_EP, "getvar:identify".as_bytes(), timeout).ok();
  // while let Ok(_s) = do_read_bulk(h) {
  //   print!(".");
  //   io::stdout().flush().ok();
  //   std::thread::sleep(Duration::from_millis(250));
  // }
  // println!("");

  // h.write_bulk(ADNL_OUT_EP, "getvar:identify".as_bytes(), timeout).ok();
  do_write_blk_cmd(h, "getvar:identify").unwrap();
  do_read_bulk(h).ok();

  // h.write_bulk(ADNL_OUT_EP, "getvar:identify".as_bytes(), timeout).ok();
  do_write_blk_cmd(h, "getvar:identify").unwrap();
  do_read_bulk(h).ok();

  // h.write_bulk(ADNL_OUT_EP, "getvar:getchipinfo-1".as_bytes(), timeout).ok();
  do_write_blk_cmd(h, "getvar:getchipinfo-1").unwrap();
  do_read_bulk(h).ok();

  // match h.read_bulk(ADNL_IN_EP, &mut buf, timeout) {
  //   Ok(len) => {
  //     println!("Read {len} bytes!");
  //     println!("{}",String::from_utf8_lossy(&buf));
  //   }
  //   Err(e) => println!("Failed to read: {:?}", e)
  // }

  do_write_blk_cmd(h, "getvar:downloadsize").unwrap();
  // if let Ok(len) = h.write_bulk(ADNL_OUT_EP, "getvar:downloadsize".as_bytes(), timeout) {
  //   println!("Wrote {len} bytes!");
  // } else {
  //   println!("Failed to write");
  //   return
  // }

  let mut dlsize: u32 = 0;

  match do_read_bulk(h) {
    Ok(msg) => dlsize = u32::from_str_radix(msg.to_lowercase().replace("0x","").as_str(),16).unwrap(),
    Err(e) => {
      println!("Failed to get download size: {}",e);
      return
    }
  }

  if let Ok(len) = h.write_bulk(ADNL_OUT_EP, format!("download:{:08X}",dlsize).as_bytes(), timeout) {
    println!("Wrote {len} bytes!");
  } else {
    println!("Failed to write");
    return
  }


  do_read_bulk(h).unwrap();
  // write the data now
  for ch in data[0..dlsize as usize].chunks(0x4000 as usize) {
    if let Ok(len) = h.write_bulk(ADNL_OUT_EP, ch, timeout) {
      println!("Wrote {len} bytes!");
    } else {
      println!("Failed to write");
      return
    }
  }

  do_read_bulk(h).unwrap();

  if let Ok(len) = h.write_bulk(ADNL_OUT_EP, "boot".as_bytes(), timeout) {
    println!("Wrote {len} bytes!");
  } else {
    println!("Failed to write");
    return
  }


  do_read_bulk(h).unwrap();

  // match h.read_bulk(ADNL_IN_EP, &mut buf, timeout) {
  //   Ok(len) => {
  //     println!("Read {len} bytes!");
  //     println!("{}",String::from_utf8_lossy(&buf));
  //   }
  //   Err(e) => println!("Failed to read: {:?}", e)
  // }


  std::thread::sleep(Duration::from_millis(500));

  do_write_blk_cmd(h, "getvar:identify").unwrap();
  do_read_bulk(h).ok();


  // this next part is 'reveresed engineered from a USB trace of the adnl tool
  // so it could be...fragile
  do_write_blk_cmd(h, "getvar:cbw").unwrap();
  do_read_bulk(h).unwrap();

  // match h.read_bulk(ADNL_IN_EP, &mut buf, timeout) {
  //   Ok(len) => {
  //     println!("Read {len} bytes!");
  //     println!("{}",String::from_utf8_lossy(&buf));
  //   }
  //   Err(e) => println!("Failed to read: {:?}", e)
  // }


  let data = if let Ok(data) = std::fs::read(PathBuf::from(bl2.as_ref())) {
    data
  } else {
    println!("Error: Failed to read {}", bl1.as_ref());
    return
  };


  struct WriteDef {
    addr: u32,
    size: usize,
    sum: u32,
    last: bool,
  }

  let offsets = [
    WriteDef { addr: 0x64000, size: 0x9600, sum: 0xac6a701c, last: false},
    WriteDef { addr: 0x8c000, size: 0x9600, sum: 0, last: false},
    WriteDef { addr: 0x96000, size: 0x9600, sum: 0, last: false},
    WriteDef { addr: 0x6e000, size: 0x9600, sum: 0, last: false},
    WriteDef { addr: 0x78000, size: 0x9600, sum: 0, last: false},
    WriteDef { addr: 0x82000, size: 0x9600, sum: 0, last: false},
    WriteDef { addr: 0x42000, size: 0x11000, sum: 0, last: false},
    WriteDef { addr: 0x53000, size: 0x11000, sum: 0, last: false},
    WriteDef { addr: 0xa4000, size: 0x8000, sum: 0, last: false},
    WriteDef { addr: 0xac000, size: 0x26C260, sum: 0, last: true},

  ].into_iter();


  for wd in offsets {

    dlsize = 0x2000;
    // do_write_blk_cmd(h, format!("download:{:08X}",dlsize)).unwrap();
    // do_read_bulk(h).unwrap();
    // println!("Start: {}", start_off);
    // let size = 0x9600;
    let i = wd.addr as usize;
    let l = wd.size + wd.addr as usize;
    let dsl = &data[i..l];

    for ch in dsl.chunks(dlsize as usize) {
      do_write_blk_cmd(h, format!("download:{:08X}",ch.len())).unwrap();
      do_read_bulk(h).unwrap();
      if let Ok(len) = h.write_bulk(ADNL_OUT_EP, &ch, timeout) {
        println!("Wrote {len} bytes!");
      } else {
        println!("Failed to write");
        return
      }
      do_read_bulk(h).unwrap();
    }


    do_write_blk_cmd(h, "setvar:checksum").unwrap();
    do_read_bulk(h).unwrap();

    let buf = wd.sum.to_le_bytes();
    if let Ok(len) = h.write_bulk(ADNL_OUT_EP, &buf, timeout) {
      println!("Wrote {len} bytes!");
    } else {
      println!("Failed to write");
      return
    }
    do_read_bulk(h).unwrap();

    do_write_blk_cmd(h, "getvar:cbw").unwrap();
    do_read_bulk(h).unwrap();

    // if !wd.last {
      do_write_blk_cmd(h, "getvar:identify").unwrap();
      do_read_bulk(h).ok();

      do_write_blk_cmd(h, "getvar:cbw").unwrap();
      do_read_bulk(h).unwrap();
    // }

  }

  dlsize = data.len() as u32;

  std::thread::sleep(Duration::from_millis(1000));

  // now write the entire file to flash/boot partition
  do_write_blk_cmd(h, "oem disk_initial 1").unwrap();
  do_read_bulk(h).unwrap();
  do_write_blk_cmd(h, format!("oem mwrite {:08X} normal store bootloader",dlsize)).unwrap();
  do_read_bulk(h).unwrap();

  for ch in data.chunks(0x4000) {
    if let Ok(len) = h.write_bulk(ADNL_OUT_EP, &ch, timeout) {
      println!("Wrote {len} bytes!");
    } else {
      println!("Failed to write");
      return
    }
  }
  do_read_bulk(h).unwrap();

  do_write_blk_cmd(h, "reboot").unwrap();
  do_read_bulk(h).unwrap();

}
