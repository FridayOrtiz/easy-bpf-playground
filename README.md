# easy-bpf-playground
A template repository for quickly creating one-off eBPF experiments.

## Building

Once you have your BPF code written, `cd` to the `bpf/` folder and run `docker compose up`. That should be all you need to build the `filter_program_x86_64`.

Once this is done, from the project root `cargo build` should build your executable with the filter bundled in. If you want to run it with `cargo`, you may need to invoke it with root privileges. I recommend creating an `alias scargo='sudo -E $HOME/.cargo/bin/cargo'` so you can easily `scargo run` during testing. 

**Note:** The template will _not_ build and run as-is. You will need to provide a BPF filter and modify `main.rs` to load the appropriate filter type. If you want an example of this template in action, check out [timebase](https://github.com/FridayOrtiz/timebase).
