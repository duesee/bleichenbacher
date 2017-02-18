def typecheck(f):
    """
    Taken from "Python 3 - Das umfassende Handbuch"
    """
    def decorated(*args, **kws):
        for i, name in enumerate(f.__code__.co_varnames):
            argtype = f.__annotations__.get(name)

            # Only check if annotation exists and it is as a type
            if isinstance(argtype, type):
                # First len(args) are positional...
                if i < len(args):
                    if not isinstance(args[i], argtype):
                        raise TypeError("Positional argument {0} has type {1} but expected was type {2}.".format(i, type(args[i]), argtype))
                # ...after that check keywords
                elif name in kws:
                    if not isinstance(kws[name], argtype):
                        raise TypeError("Keyword argument '{0}' has type {1} but expected was type {2}.".format(name, type(kws[name]), argtype))

        res = f(*args, **kws)
        restype = f.__annotations__.get('return')

        # Check return type
        if isinstance(restype, type):
            if not isinstance(res, restype):
                raise TypeError("Return value has type {0} but expected was type {1}.".format(type(res), restype))

        return res

    return decorated
