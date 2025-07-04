# DLL_Injection
This is a sort of stealthy way of injection (An example of a dll is included using MessageBoxA, you will have to make a new crate for it using cargo new name --lib, and then build it using
cargo build --release). You will find the dll in the release folder, just copy that path into the injector code and it should work. Before I get into the concepts here is an image of it working.
![image](https://github.com/user-attachments/assets/c689d965-5de2-498e-8a09-03db953e265f)
![image](https://github.com/user-attachments/assets/5d5a7536-afd2-4cc1-b2ce-b8083cf2491e)

Now lets dive into how this works a little.



