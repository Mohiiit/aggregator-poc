use std::fs;
use std::path::{Path, PathBuf};
use cairo_vm::Felt252;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use starknet_os::{
    runner::run_aggregator
};
use starknet_os::hint_processor::aggregator_hint_processor::{AggregatorInput, DataAvailability};
use starknet_types_core::felt::Felt;

#[derive(Debug)]
pub enum FactError {
    OutputBuiltinNoSegmentInfo,
    OutputSegmentUnexpectedRelocatable(usize),
    InvalidSegment,
    FilterOutputError,
}

pub fn get_program_output(cairo_pie: &CairoPie, is_aggregator: bool) -> Result<Vec<Felt252>, FactError> {
    let segment_info =
        cairo_pie.metadata.builtin_segments.get(&BuiltinName::output).ok_or(FactError::OutputBuiltinNoSegmentInfo)?;

    let mut output = vec![Felt252::from(0); segment_info.size];
    let mut insertion_count = 0;
    let cairo_program_memory = &cairo_pie.memory.0;

    for ((index, offset), value) in cairo_program_memory.iter() {
        if *index == segment_info.index as usize {
            match value {
                MaybeRelocatable::Int(felt) => {
                    output[*offset] = *felt;
                    insertion_count += 1;
                }
                MaybeRelocatable::RelocatableValue(_) => {
                    return Err(FactError::OutputSegmentUnexpectedRelocatable(*offset));
                }
            }
        }
    }

    if insertion_count != segment_info.size {
        return Err(FactError::InvalidSegment);
    }

    Ok(if is_aggregator { filter_output_from_program_output(output)? } else { output })
}

pub fn filter_output_from_program_output(output: Vec<Felt252>) -> Result<Vec<Felt252>, FactError> {
    // TODO: Implement the actual filtering logic based on the Python code
    // For now, returning the output as-is
    Ok(output)
}

// Convert Felt252 to starknet Felt
fn felt252_to_felt(felt252: Felt252) -> Felt {
    let bytes = felt252.to_bytes_be();
    Felt::from_bytes_be(&bytes)
}

// Build aggregator input following the Python logic
pub fn build_aggregator_input(
    cairo_pies: Vec<CairoPie>,
    aggregator_type: &str
) -> Result<Vec<Felt>, Box<dyn std::error::Error + Send + Sync>> {
    let mut aggregator_input = Vec::new();
    
    // Add redundant hashes based on aggregator type
    let redundant_hashes = match aggregator_type {
        "snos" => vec![],
        "dummy" => vec![Felt::ZERO, Felt::ZERO, Felt::ZERO],
        _ => return Err(format!("Unknown aggregator type: {}", aggregator_type).into()),
    };
    
    aggregator_input.extend(redundant_hashes);
    
    // Add number of children
    let num_children = cairo_pies.len();
    aggregator_input.push(Felt::from(num_children));
    
    println!("Building aggregator input for {} children", num_children);
    
    // Process each child CairoPIE
    for (idx, cairo_pie) in cairo_pies.into_iter().enumerate() {
        println!("Processing child {}/{}", idx + 1, num_children);
        
        // Get program output (is_aggregator = false)
        let child_output = get_program_output(&cairo_pie, false)
            .map_err(|e| format!("Failed to get program output: {:?}", e))?;
        
        // output_add_ups_values_size = 2 (from Python code)
        let output_size = child_output.len() + 2;
        
        // TODO: Compute actual program hash - using placeholder for now
        let program_hash = Felt::from_hex_unchecked("0x1743748b74de4465a173b516c7b7e9f746f4b1557d968b3fc618c76485e241a"); // Placeholder
        
        println!("  Output size: {}, Program hash: {:?}", output_size, program_hash);
        
        // Add: [output_size, program_hash, ...child_output...]
        aggregator_input.push(Felt::from(output_size));
        aggregator_input.push(program_hash);
        
        // Convert and add child output
        for felt252 in child_output {
            aggregator_input.push(felt252_to_felt(felt252));
        }
    }
    
    println!("Total aggregator input size: {} felts", aggregator_input.len());
    Ok(aggregator_input)
}

// Read and process multiple CairoPIE files from a directory
pub fn process_cairo_pies_from_directory(dir_path: &Path) -> Result<Vec<CairoPie>, Box<dyn std::error::Error + Send + Sync>> {
    let mut cairo_pies = Vec::new();
    
    // Read all .zip files from the directory
    let entries = fs::read_dir(dir_path)
        .map_err(|e| format!("Failed to read directory {:?}: {}", dir_path, e))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();
        
        // Process only .zip files (assuming CairoPIE files are stored as zips)
        if path.extension().and_then(|s| s.to_str()) == Some("zip") {
            println!("Loading CairoPIE from: {:?}", path);
            
            // Read the CairoPIE from the zip file
            let cairo_pie = CairoPie::read_zip_file(&path)
                .map_err(|e| format!("Failed to read CairoPIE from {:?}: {}", path, e))?;
            
            cairo_pies.push(cairo_pie);
        }
    }
    
    println!("Loaded {} CairoPIE files", cairo_pies.len());
    Ok(cairo_pies)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let layout: LayoutName = LayoutName::all_cairo;
    
    // Directory containing CairoPIE zip files
    let cairo_pie_dir = Path::new("/Users/mohit/Desktop/karnot/aggregator-poc/cairo_pies");
    let aggregator_type = "snos"; // or "dummy"
    
    // Process all CairoPIE files and build aggregator input
    let bootloader_output = if cairo_pie_dir.exists() {
        println!("Processing CairoPIE files from: {:?}", cairo_pie_dir);
        
        // Load all CairoPIE files
        let cairo_pies = process_cairo_pies_from_directory(cairo_pie_dir)?;
        
        if cairo_pies.is_empty() {
            println!("No CairoPIE files found in directory");
            None
        } else {
            // Build aggregator input according to the format
            let aggregator_input = build_aggregator_input(cairo_pies, aggregator_type)?;
            Some(aggregator_input)
        }
    } else {
        println!("No CairoPIE directory found at {:?}, running without bootloader output", cairo_pie_dir);
        None
    };
    
    let aggregator_input = AggregatorInput {
        bootloader_output,
        full_output: false,
        debug_mode: true,
        chain_id: Felt::from_hex_unchecked("0x534e5f5345504f4c4941"),
        da: DataAvailability::Blob(PathBuf::from("./test.txt")),
        public_keys: None,
        fee_token_address: Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"),
    };
    
    println!("Running aggregator...");
    let aggregator_output = run_aggregator(layout, aggregator_input).expect("issue with the aggregator");
    println!("Aggregator output: {:?}", aggregator_output.aggregator_output);
    
    let aggregator_cairo_pie = aggregator_output.cairo_pie;
    aggregator_cairo_pie.run_validity_checks().expect("issue with the checks");
    aggregator_cairo_pie.write_zip_file(Path::new("./test_aggregator.zip"), true).expect("fail to write to zip");
    
    println!("Successfully wrote aggregator CairoPIE to ./test_aggregator.zip");
    Ok(())
}
