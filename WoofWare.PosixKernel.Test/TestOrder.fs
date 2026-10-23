namespace WoofWare.PosixKernel.Test

/// NUnit hands fixtures to its workers in name order, and a fixture with
/// `[<Order(n)>]` before every fixture without one. A long test handed out
/// late runs on alone at the end of the suite, with the other workers idle, so
/// a fixture whose longest test takes more than about 25 s on CI starts first.
[<RequireQualifiedAccess>]
module TestOrder =

    /// The `Order` of a fixture holding a test long enough to hold up the end
    /// of the suite if it started late.
    [<Literal>]
    let LongRunning = 0
