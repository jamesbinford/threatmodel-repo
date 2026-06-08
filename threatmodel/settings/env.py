def env_bool(environ, name, default=False):
    value = environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(environ, name, default=0):
    value = environ.get(name)
    if value is None or value == "":
        return default
    return int(value)
