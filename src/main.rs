pub mod inject;
fn main() {
    let processName= "notepad.exe";
    let dllPath = "C:\\Users\\jacks\\CS462\\httpServer\\target\\debug\\httpServer.dll";
    inject::inject(processName,dllPath);    
}




