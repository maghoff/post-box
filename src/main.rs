extern crate base64;
extern crate crypto;
extern crate getopts;
extern crate rotor;
extern crate rotor_http;

use std::path::PathBuf;
use std::time::Duration;
use rotor::{Scope, Time};
use rotor_http::server::{RecvMode, Server, Head, Response, Fsm};
use rotor::mio::tcp::TcpListener;
use rotor::mio::unix::UnixListener;

struct Context {
    file_root: PathBuf,
    key: Vec<u8>,
    root_url: String,
}

#[derive(Debug, Clone)]
enum PostBox {
    Store { name: String },
    PageNotFound,
    MethodNotAllowed { allow: &'static [u8] },
}

impl Server for PostBox {
    type Seed = ();
    type Context = Context;

    fn headers_received(
        _seed: (),
        head: Head,
        _res: &mut Response,
        scope: &mut Scope<Context>
    )
        -> Option<(Self, RecvMode, Time)>
    {
        use self::PostBox::*;

        Some(match head.path {
            p if p.starts_with("/") && p.len() > 2 =>
                match head.method {
                    "POST" => (
                        Store { name: p[1..].to_owned() },
                        RecvMode::Buffered(1024 * 1024),
                        scope.now() + Duration::new(10, 0),
                    ),
                    _ => (
                        MethodNotAllowed { allow: b"POST" },
                        RecvMode::Buffered(1024),
                        scope.now() + Duration::new(0, 1),
                    )
                },
            _ => (
                PageNotFound,
                RecvMode::Buffered(1024),
                scope.now() + Duration::new(0, 1),
            )
        })
    }

    fn request_received(self, data: &[u8], res: &mut Response, scope: &mut Scope<Context>)
        -> Option<Self>
    {
        use self::PostBox
    ::*;
        match self {
            Store { name } => {
                use crypto::mac::Mac;

                let mut hmac = crypto::hmac::Hmac::new(crypto::md5::Md5::new(), &scope.key);
                hmac.input(name.as_bytes());
                let scramble = &base64::encode_mode(hmac.result().code(), base64::Base64Mode::UrlSafe)[0..21];

                let dirname = scope.file_root.join(scramble);
                assert!(dirname.starts_with(&scope.file_root));

                println!("{:?}: {:?}", &dirname.join(&name), &data);

                use std::fs::*;
                use std::io::Write;
                create_dir(&dirname).unwrap();
                let mut f = File::create(dirname.join(&name)).unwrap();
                f.write_all(data).unwrap();

                let url = format!("{}{}/{}", &scope.root_url, &scramble, &name);
                let response = &url.as_bytes();

                res.status(200, "OK");
                res.add_length(response.len() as u64).unwrap();
                res.add_header("Location", &url.as_bytes()).unwrap();
                res.done_headers().unwrap();
                res.write_body(response);
                res.done();
            }
            PageNotFound => {
                let data = b"404 Not Found\n";
                res.status(404, "Not Found");
                res.add_length(data.len() as u64).unwrap();
                res.done_headers().unwrap();
                res.write_body(data);
                res.done();
            }
            MethodNotAllowed { allow } => {
                let data = b"405 Method Not Allowed\n";
                res.status(405, "Method Not Allowed");
                res.add_length(data.len() as u64).unwrap();
                res.add_header("Allow", allow).unwrap();
                res.done_headers().unwrap();
                res.write_body(data);
                res.done();
            }
        }
        None
    }

    fn request_chunk(self, _chunk: &[u8], _response: &mut Response, _scope: &mut Scope<Context>)
        -> Option<Self>
    {
        unreachable!();
    }

    /// End of request body, only for Progressive requests
    fn request_end(self, _response: &mut Response, _scope: &mut Scope<Context>)
        -> Option<Self>
    {
        unreachable!();
    }

    fn timeout(self, _response: &mut Response, _scope: &mut Scope<Context>)
        -> Option<(Self, Time)>
    {
        unimplemented!();
    }

    fn wakeup(self, _response: &mut Response, _scope: &mut Scope<Context>)
        -> Option<Self>
    {
        unimplemented!();
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let _program = args[0].pop();

    let mut opts = getopts::Options::new();
    opts.optopt("", "root", "Set output root path", "PATH");
    opts.optopt("", "tcp", "Listen to ADDR on TCP", "ADDR");
    opts.optopt("", "unix", "Listen to FILE as a Unix named socket", "FILE");
    opts.optopt("", "key", "Use KEY as HMAC key", "KEY");
    opts.optopt("", "url", "Use URL as base URL for generated URLs", "URL");
    let matches = opts.parse(args).unwrap();

    let event_loop = rotor::Loop::new(&rotor::Config::new()).unwrap();

    let mut loop_inst = event_loop.instantiate(Context {
        file_root: PathBuf::from(&matches.opt_str("root").unwrap_or("".to_owned())),
        key: base64::decode(&matches.opt_str("key").expect("You must specify HMAC key with --key")).expect("KEY must be correctly base64 encoded"),
        root_url: matches.opt_str("url").expect("You must specify root url with --url"),
    });

    if let Some(unix) = matches.opt_str("unix") {
        let _lst = UnixListener::bind(&unix).unwrap();
        println!("Listening to {}", &unix);
//        loop_inst.add_machine_with(|scope| Fsm::<PostBox, _>::new(lst, (), scope)).unwrap();
        panic!("Somehow it will not compile with the option to do either Unix or TCP");
    } else {
        let addr = matches.opt_str("tcp").unwrap_or("127.0.0.1:2000".to_owned());
        let lst = TcpListener::bind(&addr.parse().unwrap()).unwrap();
        println!("Listening to {}", &lst.local_addr().unwrap());
        loop_inst.add_machine_with(|scope| Fsm::<PostBox, _>::new(lst, (), scope)).unwrap();
    }

    loop_inst.run().unwrap();
}
