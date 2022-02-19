import itertools

def floorlog2(x):
    return x.bit_length() - 1

def padme(l):
    # print(f'{l=}', end=' ')
    e = floorlog2(l)
    s = floorlog2(e) + 1
    last_bits = e - s
    # print(f'{e=} {s=} lb={last_bits}', end=' ')
    bit_mask = (2 ** last_bits) - 1
    # print(f'bm={bit_mask}')
    return (l + bit_mask) & ~bit_mask

def maxlength(maxtotal, overhead):
    if padme(maxtotal) == maxtotal:
        return maxtotal - overhead

    theorymax = maxtotal - overhead
    for i in itertools.count():
        if padme(i + overhead) > maxtotal:
            return i - 1
