namespace WoofWare.PosixKernel

/// <summary>
/// Exception indicating that you've tried to do something WoofWare.PosixKernel
/// doesn't yet support.
/// </summary>
/// <remarks>
/// WoofWare.PosixKernel generally only offers behaviour that has been measured
/// on its target kernels, and throws this exception if you ask for something
/// which hasn't been measured.
/// This exception indicates a feature request for PosixKernel.
///
/// Any library function may throw this exception at any time.
/// ("WITHOUT WARRANTY… INCLUDING… FITNESS FOR A PARTICULAR PURPOSE")
///
/// WoofWare.PosixKernel operates only with immutable data structures, so you
/// can at least catch this and try to carry on yourself.
/// </remarks>
[<Sealed>]
type UnmodelledException internal (message : string) =
    inherit System.Exception (message)

/// <summary>
/// Classifies a refusal from a public entry point.
/// </summary>
/// Which exception a refusal is raised as at a public entry point. The
/// question is whether a client that follows the documentation could have
/// made the call: if it could, the model does not cover the call; if not, the
/// call is the client's mistake, and .NET's own exception for that mistake says
/// so.
[<RequireQualifiedAccess>]
type internal RefusalKind =
    /// <summary>
    /// The model does not cover what was asked.
    /// </summary>
    /// <remarks>
    /// We'll surface this to the user as <c>UnmodelledException</c>.
    /// </remarks>
    | Unmodelled
    /// <summary>
    /// The user has passed a parameter which doesn't make sense in the context of the call
    /// or of the state of the machine.
    /// </summary>
    /// <param name="parameter">The name of the function parameter whose value is inconsistent.</param>
    /// <example>
    /// The user attempted to spawn a new process specifying a working directory which is not a valid Unix path.
    /// </example>
    /// <remarks>
    /// We'll surface this to the user as <c>ArgumentException</c>.
    /// </remarks>
    | Contradictory of parameter : string
    /// <summary>
    /// The user has passed a parameter which is outside the range any machine could accept.
    /// </summary>
    /// <example>
    /// The user attempted to create a process with a PID that exceeds the machine's highest possible PID.
    /// </example>
    /// <param name="parameter">The name of the function parameter whose value is out of range.</param>
    /// <remarks>
    /// We'll surface this to the user as <c>ArgumentOutOfRangeException</c>.
    /// </remarks>
    | OutOfRange of parameter : string
    /// <summary>
    /// The user passed a null parameter.
    /// </summary>
    /// <remarks>
    /// This is impossible if the user is using the library as documented, but they may encounter
    /// this error if e.g. they used <c>Unchecked.defaultof</c> to manufacture nulls.
    ///
    /// We'll surface this to the user as <c>ArgumentNullException</c>.
    /// </remarks>
    /// <param name="parameter">The name of the function parameter whose value is null.</param>
    | Null of parameter : string
    /// <summary>
    /// The user tried to call a syscall which doesn't exist on this platform.
    /// </summary>
    /// <remarks>
    /// We'll surface this to the user as <c>PlatformNotSupportedException</c>.
    /// </remarks>
    /// <example>
    /// Darwin has no <c>setresuid</c>, so can't change the user ID of a process.
    /// </example>
    | NotOnPlatform

[<RequireQualifiedAccess>]
module internal Refusal =

    /// <summary>
    /// Convert the given <c>RefusalKind</c> to an exception suitable for throwing to the user.
    /// </summary>
    let exceptionOf (operation : string) (kind : RefusalKind) (description : string) : exn =
        let message = $"%s{operation}: %s{description}"

        match kind with
        | RefusalKind.Unmodelled -> UnmodelledException message
        | RefusalKind.Contradictory parameter -> System.ArgumentException (message, parameter)
        | RefusalKind.OutOfRange parameter -> System.ArgumentOutOfRangeException (parameter, message)
        | RefusalKind.Null parameter -> System.ArgumentNullException (parameter, message)
        | RefusalKind.NotOnPlatform -> System.PlatformNotSupportedException message

    /// <summary>
    /// Extract the result from <c>result</c>, or throw the exception corresponding to its error case.
    /// </summary>
    let orRaise<'Answer, 'Refusal>
        (operation : string)
        (kind : 'Refusal -> RefusalKind)
        (describe : 'Refusal -> string)
        (result : Result<'Answer, 'Refusal>)
        : 'Answer
        =
        match result with
        | Ok answer -> answer
        | Error refusal -> raise (exceptionOf operation (kind refusal) (describe refusal))
