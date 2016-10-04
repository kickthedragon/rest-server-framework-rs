//! Macros module.

#[macro_export]
macro_rules! get_token {
    ($req:ident) => (
        match $req.headers.get::<::iron::headers::Authorization<::iron::headers::Bearer>>() {
        Some(auth) => {
            match ::v1::oauth::AccessToken::from_token(&auth.0.token) {
                Ok(token) => if !token.has_expired() {
                    token
                } else {
                    let mut res = ::iron::Response::new();
                    let _ = res.set_mut(::rustc_serialize::json::encode(
                                    &::dto::ResponseDTO::new("the token has expired")).unwrap())
                               .set_mut(::iron::status::Forbidden);
                    return Ok(res);
                },
                Err(_) => {
                    let mut res = ::iron::Response::new();
                    let _ = res.set_mut(::iron::status::BadRequest);
                    return Ok(res);
                }
            }
        }
        None => {
            let mut res = Response::new();
            let _ = res.set_mut(json::encode(
                            &ResponseDTO::new("a bearer token must be provided")).unwrap())
                       .set_mut(::iron::status::Forbidden);
            return Ok(res);
        }
    }
)}

#[macro_export]
macro_rules! param {
    ($req: ident, $param: expr) => (
        match option_param!($req, $param) {
            Some(param) => param,
            None => {
                let mut res = Response::new();
                let _ = res.set_mut(::iron::status::BadRequest);
                return Ok(res);
            }
        }
    )
}

#[macro_export]
macro_rules! option_param {
    ($req: ident, $param: expr) => (
        match $req.extensions.get::<::router::Router>() {
            Some(params) => {
                match params.find($param) {
                    Some(id) => Some(id.to_owned()),
                    None => None
                }
            }
            None => None
        }
    )
}
