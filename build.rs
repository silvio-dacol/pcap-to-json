fn main() {
    // Tell Cargo where to find the Npcap SDK libraries
    println!("cargo:rustc-link-search=native=C:\\Program Files\\Npcap\\sdk\\Lib\\x64");
    
    // Link against wpcap and Packet libraries
    println!("cargo:rustc-link-lib=wpcap");
    println!("cargo:rustc-link-lib=Packet");
    
    // Tell Cargo to rerun this build script if the SDK path changes
    println!("cargo:rerun-if-changed=build.rs");
}
