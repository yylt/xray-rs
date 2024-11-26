use xray_rs::root;

fn main() {
    match root::execute() {
        Err(e) => {
            println!("execute error: {e}");
        }
        _ => {}
    }
}