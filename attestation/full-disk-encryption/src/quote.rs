use crate::td_report::TDReport;
use anyhow::{anyhow, Ok, Result};

pub fn retrieve_quote(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    // 1. tdreport_data
    let report_data = tdx_attest_rs::tdx_report_data_t { d: *report_data };

    // 2.1 tdreport
    let mut tdx_report = tdx_attest_rs::tdx_report_t { d: [0; 1024usize] };
    let result = tdx_attest_rs::tdx_att_get_report(Some(&report_data), &mut tdx_report);
    if result != tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(anyhow!("Failed to get the report."));
    }
    println!("TDX Report Retrieved!");
    // 2.2 uuid
    let _td_info = TDReport::new(tdx_report.d).td_info;
    let mut hex: Vec<String> = _td_info.rtmr_0.iter().map(|n| format!("{:02x}", n)).collect();
    let mut hex_string = hex.join(""); 
    //println!("RTMR 0: {:?}", hex_string);

    hex = _td_info.rtmr_1.iter().map(|n| format!("{:02x}", n)).collect();
    hex_string = hex.join("");
    //println!("RTMR 3: {:?}", hex_string);

    hex = _td_info.rtmr_2.iter().map(|n| format!("{:02x}", n)).collect();
    hex_string = hex.join("");
    //println!("RTMR 3: {:?}", hex_string);
    
    hex = _td_info.rtmr_3.iter().map(|n| format!("{:02x}", n)).collect();
    hex_string = hex.join("");
    //println!("RTMR 3: {:?}", hex_string);


    hex = _td_info.mrtd.iter().map(|n| format!("{:02x}", n)).collect();
    hex_string = hex.join("");
    //println!("MRTD : {:?}", hex_string);

    let _tee_tcb_info = TDReport::new(tdx_report.d).tee_tcb_info;
    
    hex = _tee_tcb_info.mrseam.iter().map(|n| format!("{:02x}", n)).collect();
    hex_string = hex.join("");
    //println!("MRSEAM: {:?}", hex_string);

    hex = _tee_tcb_info.mrsignerseam.iter().map(|n| format!("{:02x}", n)).collect();
    hex_string = hex.join("");
    //println!("MRSIGNERSEAM: {:?}", hex_string);
        
    // 3. quote
    let mut selected_att_key_id = tdx_attest_rs::tdx_uuid_t { d: [0; 16usize] };
    let (result, quote) = tdx_attest_rs::tdx_att_get_quote(
        Some(&report_data),
        None,
        Some(&mut selected_att_key_id),
        0,
    );
    if result != tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(anyhow!("Failed to get the quote."));
    }
    let quote_bytes = quote.expect("Failed to parse the quote");
    println!("TDX Quote Retrieved!");
    //println!("Report Data: {:?}", quote_bytes);
    Ok(quote_bytes)
}
