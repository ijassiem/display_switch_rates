def create_matrix(switch_dict, opts):
    mleaves = opts.maxleaves
    cols = len(switch_dict.keys()) + 1  # length or number of elements in dictionary

    if opts.display == 'spines':
        lines = mleaves * 2 + 1 #  max 36 leaves, *2 for tx and rx
    else:
        # Find how many ethernet ports there are on the leaves
        port_list = []
        lines = 0
        for k, v in switch_dict.iteritems():  # same as .items(), display keys and values
            for port in v.keys():  # port = Eth1/1 or Eth1/n
                try:
                    port_list.index(port)
                except ValueError:
                    port_list.append(port)
        port_list = sorted(port_list, key=natural_keys)
        #lines = len(port_list) * 7 + 1 # was *6, was *2
        lines = len(port_list) * 2 + 1

    matrix = [[[0 for x in range(cols)] for y in range(lines)] for z in range(5)]  # creates matrix, a 3-D list of zeros, lines x cols
    return matrix