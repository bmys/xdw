def flatten(d, separator='_', prefix=''):
    return {prefix + separator + k if prefix else k: v
            for kk, vv in d.items()
            for k, v in flatten(vv, separator, kk).items()
            } if isinstance(d, dict) else {prefix: d}
