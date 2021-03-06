#!/usr/bin/env python
# 
# Author: Dave Hull
# License: We don't need no stinking license. I hereby place
# this in the public domain.
#
# Todo: 
# 
# It's a secret.

def check_args(args):
    print "[+] Checking command line arguments."

    try:
        if args.stddevs > 0:
            print "[+] Outlier threshold is %s" % args.stddevs
        else:
            raise Exception
    except: 
        print "[+] --devs must be a positive number (floating points are acceptable)."
        parser.print_help()
        quit()

    if args.aspect1 == args.aspect2:
        print "[+] --aspect1 and --aspect2 are the same metadata element. They must be different."
        parser.print_help()
        quit()

    if args.aspect1 not in ['atime', 'ctime', 'crtime', 'mtime', 'meta_addr']:
        print "[+] Invalid metadata element given for --aspect1: %s" % args.aspect1
        parser.print_help()
        quit()

    if args.aspect2 not in ['atime', 'ctime', 'crtime', 'mtime', 'meta_addr']:
        print "[+] Invalid metadata element given for --aspect2: %s" % args.aspect2
        parser.print_help()
        quit()

    try:
        fi = open(args.filename, 'rb')
    except:
        print "[+] Could not open %s for reading." % (args.filename)
        parser.print_help()
        quit()
    if fi.read(1) == '0':
        print "[+] %s may be a bodyfile." % (args.filename)
    else:
        print "[+] %s does not appear to be a bodyfle." % (args.filename)
        parser.print_help()
        quit()
    fi.close()

    if args.mode not in ['and', 'or']:
        print "[+] Invalid --mode argument: %s" % args.mode
        parser.print_help()
        quit()

    return


def get_deviants(args):
    zero_cnt = aspect1_zero_cnt = aspect2_zero_cnt = aspect2_total =\
    aspect1_total = fname_skip_cnt = dev_sum1 = dev_sum2 = bad_line =\
    file_dev1 = file_dev2 = total_lines = included_lines = 0
    aspect1_time  = aspect2_time = True
    current_path  = None
    stddevs       = float(args.stddevs)
    dev1 = {}
    dev2 = {}
    path = {}

    fi = open(args.filename, 'rb')
    for line in fi:
        total_lines += 1
        try: 
            md5,ppath,inode,mode,uid,gid,size,atime,mtime,ctime,crtime = line.rstrip().split("|")
        except:
            bad_line += 1
            continue
        
        if args.aspect1 == 'meta_addr': 
            meta = inode.split("-")
            aspect1 = int(meta[0])
            aspect1_time = False
        elif args.aspect1 == 'atime':
            aspect1 = int(atime)
        elif args.aspect1 == 'mtime':
            aspect1 = int(mtime)
        elif args.aspect1 == 'ctime':
            aspect1 = int(ctime)
        elif args.aspect1 == 'crtime':
            aspect1 = int(crtime)

        if aspect1 == 0:
            aspect1_zero_cnt += 1
            continue

        if args.aspect2 == 'meta_addr': 
            meta = inode.split("-")
            aspect2 = int(meta[0])
            aspect2_time = False
        elif args.aspect2 == 'atime':
            aspect2 = int(atime)
        elif args.aspect2 == 'mtime':
            aspect2 = int(mtime)
        elif args.aspect2 == 'ctime':
            aspect2 = int(ctime)
        elif args.aspect2 == 'crtime':
            aspect2 = int(crtime)

        if aspect2 == 0:
            aspect2_zero_cnt += 1
            continue

        fname = os.path.basename(ppath).rstrip()
        if fname == ".." or fname == ".":
            fname_skip_cnt += 1
            continue

        pname = os.path.dirname(ppath).rstrip()
        if pname not in path:
            path[pname] = {}

        path[pname][fname] = aspect1, aspect2

    print "[+] Discarded %d files with 0 for %s." % (aspect1_zero_cnt, args.aspect1) 
    print "[+] Discarded %d files with 0 for %s." % (aspect2_zero_cnt, args.aspect2) 
    print "[+] Discarded %d files named .. or ." % (fname_skip_cnt)
    print "[+] Discarded %d bad lines from %s." % (bad_line, args.filename)
    print "Metadata %s %s %s outliers that are more than %2.2f standard deviations from average values for their respective paths." % (args.aspect1, args.mode, args.aspect2, stddevs)
    print "====================================================================================================================================="

    items = [(pname, fname) for pname, fname in path.items()]
    items.sort()

    '''
    for pname, fname in path.items():
        if pname == "/usr/sbin":
            print "pname: ", pname
            for filename, meta in fname.items():
                meta1, meta2 = meta
                print "%s, %d, %d " % (filename, meta1, meta2)
    '''
    for pname, fname in items:
        files = [(filename, coord) for filename, coord in fname.items()]
        files.sort()
        file_cnt = len(files)
        if file_cnt > 1:
            for filename, coord in files:
                aspect1_total += coord[0]
                aspect2_total += coord[1]

            avg1 = aspect1_total / file_cnt
            avg2 = aspect2_total / file_cnt

            for filename, coord in files:
                dev1[filename] = coord[0] - avg1
                dev2[filename] = coord[1] - avg2
                dev_sum1 += (dev1[filename] ** 2)
                dev_sum2 += (dev2[filename] ** 2)

            std_dev1 = math.sqrt((dev_sum1 * 1.0) / (file_cnt * 1.0))
            std_dev2 = math.sqrt((dev_sum2 * 1.0) / (file_cnt * 1.0))

            no_header = True
            outlier1 = stddevs * std_dev1
            outlier2 = stddevs * std_dev2
            for filename, coord in files:
                if args.mode == 'and':
                    if math.fabs(dev1[filename]) > outlier1 and math.fabs(dev2[filename]) > outlier2:

                        included_lines += 1

                        file_dev1 = dev1[filename] / std_dev1
                        file_dev2 = dev2[filename] / std_dev2

                        if no_header:
                            if aspect1_time:
                                avg1_time = strftime("%Y %m %d %H:%M:%S", gmtime(avg1))
                                aspect1_time = strftime("%Y %m %d %H:%M:%S", gmtime(coord[0]))
                            if aspect2_time:
                                avg2_time = strftime("%Y %m %d %H:%M:%S", gmtime(avg2))
                                aspect2_time = strftime("%Y %m %d %H:%M:%S", gmtime(coord[1]))
                            if aspect1_time and aspect2_time:
                                print "\nPath avg %s: %s std dev: %14.2f avg %s: %s std dev: %14.2f path: %s" % (args.aspect1, avg1_time, std_dev1, args.aspect2, avg2_time, std_dev2, pname)
                            elif aspect1_time and not aspect2_time:
                                print "\nPath avg %s: %s std dev: %14.2f avg %s: %10d std dev: %14.2f path: %s" % (args.aspect1, avg1_time, std_dev1, args.aspect2, avg2, std_dev2, pname)
                            elif aspect2_time and not aspect1_time:
                                print "\nPath avg %s: %10d std dev: %14.2f avg %s: %s std dev: %14.2f path: %s" % (args.aspect1, avg1, std_dev1, args.aspect2, avg2_time, std_dev2, pname)
                            no_header = False
                            if aspect1_time and aspect2_time:
                                print "    file %s: %s    devs: %14.2f     %s: %s    devs: %14.2f file:  %s" % (args.aspect1, aspect1_time, file_dev1, args.aspect2, aspect2_time, file_dev2, filename)
                            elif aspect1_time and not aspect2_time:
                                print "    file %s: %s    devs: %14.2f     %s: %10d    devs: %14.2f file:  %s" % (args.aspect1, aspect1_time, file_dev1, args.aspect2, coord[1], file_dev2, filename)
                            elif aspect2_time and not aspect1_time:
                                print "    file %s: %10d    devs: %14.2f     %s: %s    devs: %14.2f file:   %s" % (args.aspect1, coord[0], file_dev1, args.aspect2, aspect2_time, file_dev2, filename)
                        else:
                            if aspect1_time:
                                avg1_time = strftime("%Y %m %d %H:%M:%S", gmtime(avg1))
                                aspect1_time = strftime("%Y %m %d %H:%M:%S", gmtime(coord[0]))
                            if aspect2_time:
                                avg2_time = strftime("%Y %m %d %H:%M:%S", gmtime(avg2))
                                aspect2_time = strftime("%Y %m %d %H:%M:%S", gmtime(coord[1]))
                            if aspect1_time and aspect2_time:
                                print "    file %s: %s    devs: %14.2f     %s: %s    devs: %14.2f file:  %s" % (args.aspect1, aspect1_time, file_dev1, args.aspect2, aspect2_time, file_dev2, filename)
                            elif aspect1_time and not aspect2_time:
                                print "    file %s: %s    devs: %14.2f     %s: %10d    devs: %14.2f file:  %s" % (args.aspect1, aspect1_time, file_dev1, args.aspect2, coord[1], file_dev2, filename)
                            elif aspect2_time and not aspect1_time:
                                print "    file %s: %10d    devs: %14.2f     %s: %s    devs: %14.2f file:   %s" % (args.aspect1, coord[0], file_dev1, args.aspect2, aspect2_time, file_dev2, filename)
                else:
                    if math.fabs(dev1[filename]) > outlier1 or math.fabs(dev2[filename]) > outlier2:

                        included_lines += 1

                        if std_dev1 == 0:
                            file_dev1 = 0
                        else:
                            file_dev1 = dev1[filename] / std_dev1

                        if std_dev2 == 0:
                            file_dev2 = 0
                        else:
                            file_dev2 = dev2[filename] / std_dev2

                        if no_header:
                            if aspect1_time:
                                avg1_time = strftime("%Y %m %d %H:%M:%S", gmtime(avg1))
                                aspect1_time = strftime("%Y %m %d %H:%M:%S", gmtime(coord[0]))
                            if aspect2_time:
                                avg2_time = strftime("%Y %m %d %H:%M:%S", gmtime(avg2))
                                aspect2_time = strftime("%Y %m %d %H:%M:%S", gmtime(coord[1]))
                            if aspect1_time and aspect2_time:
                                print "\nPath avg %s: %s std dev: %14.2f avg %s: %s std dev: %14.2f path: %s" % (args.aspect1, avg1_time, std_dev1, args.aspect2, avg2_time, std_dev2, pname)
                            elif aspect1_time and not aspect2_time:
                                print "\nPath avg %s: %s std dev: %14.2f avg %s: %10d std dev: %14.2f path: %s" % (args.aspect1, avg1_time, std_dev1, args.aspect2, avg2, std_dev2, pname)
                            elif aspect2_time and not aspect1_time:
                                print "\nPath avg %s: %10d std dev: %14.2f avg %s: %s std dev: %14.2f path: %s" % (args.aspect1, avg1, std_dev1, args.aspect2, avg2_time, std_dev2, pname)
                            no_header = False
                            if aspect1_time and aspect2_time:
                                print "    file %s: %s    devs: %14.2f     %s: %s    devs: %14.2f file:  %s" % (args.aspect1, aspect1_time, file_dev1, args.aspect2, aspect2_time, file_dev2, filename)
                            elif aspect1_time and not aspect2_time:
                                print "    file %s: %s    devs: %14.2f     %s: %10d    devs: %14.2f file:  %s" % (args.aspect1, aspect1_time, file_dev1, args.aspect2, coord[1], file_dev2, filename)
                            elif aspect2_time and not aspect1_time:
                                print "    file %s: %10d    devs: %14.2f     %s: %s    devs: %14.2f file:   %s" % (args.aspect1, coord[0], file_dev1, args.aspect2, aspect2_time, file_dev2, filename)
                        else:
                            if aspect1_time:
                                avg1_time = strftime("%Y %m %d %H:%M:%S", gmtime(avg1))
                                aspect1_time = strftime("%Y %m %d %H:%M:%S", gmtime(coord[0]))
                            if aspect2_time:
                                avg2_time = strftime("%Y %m %d %H:%M:%S", gmtime(avg2))
                                aspect2_time = strftime("%Y %m %d %H:%M:%S", gmtime(coord[1]))
                            if aspect1_time and aspect2_time:
                                print "    file %s: %s    devs: %14.2f     %s: %s    devs: %14.2f file:  %s" % (args.aspect1, aspect1_time, file_dev1, args.aspect2, aspect2_time, file_dev2, filename)
                            elif aspect1_time and not aspect2_time:
                                print "    file %s: %s    devs: %14.2f     %s: %10d    devs: %14.2f file:  %s" % (args.aspect1, aspect1_time, file_dev1, args.aspect2, coord[1], file_dev2, filename)
                            elif aspect2_time and not aspect1_time:
                                print "    file %s: %10d    devs: %14.2f     %s: %s    devs: %14.2f file:   %s" % (args.aspect1, coord[0], file_dev1, args.aspect2, aspect2_time, file_dev2, filename)

            aspect1_total = aspect2_total = dev_sum1 = dev_sum2 = 0

    print "\n.:| %d lines in %s. %d files met or exceeded outlier threshold. Data reduction rate %2.4f%% |:." % (total_lines, args.filename, included_lines, 100 - float((included_lines * 1.0) / (total_lines * 1.0)))

if __name__ == '__main__':
    import re, os, math, argparse, sys
    from time import gmtime, strftime 

    parser = argparse.ArgumentParser(description = \
        'body-outliers.py compares two aspects of bodyfile metadata and ' \
        'returns a list of outliers based on the requested criteria. For ' \
        'example file creation times and metadata addresses can be selected ' \
        'as the two criteria to be used to find outliers. In this instance, ' \
        'body-outliers will calculate the average and standard deviations ' \
        'for creation times and metadata addresses for all files on a per ' \
        'direcotry basis. Files that are more than the specified number of ' \
        'standard deviations away from normal are printed to standard out ' \
        'along with their metadata values and the path they were found in ' \
        'and the paths metadata values.')
    parser.add_argument('--devs', help = '--devs defines the outlier ' \
        'threshold. Default is 1, higher values will further reduce the ' \
        'data set.', dest = 'stddevs', default = 1.0, type = float)
    parser.add_argument('--file', help = 'An fls bodyfile, see The Sleuth ' \
        'Kit.', dest = 'filename', required = True)
    parser.add_argument('--aspect1', help = '--aspect1 defines the first ' \
        'field to be used to determine outliers. The default is metadata ' \
        'addresses. Valid choices also include atime, mtime, ctime or ' \
        'crtime.', dest = 'aspect1', default = 'meta_addr')
    parser.add_argument('--aspect2', help = '--aspect2 defines the second ' \
        'field to be used to determine outliers. The default is ctime. ' \
        'Valid choices also include atime, mtime, ctime or crtime.', dest \
        = 'aspect2', default = 'ctime')
    parser.add_argument('--mode', help = '--mode can be "and" or "or" (no ' \
        'quotes) meaning that with "and" a file will only be included in ' \
        'the output if both aspect1 and aspect2 meet their respective ' \
        'outlier threshold. If --mode is "or" a file will be included in ' \
        'the output if either aspect is an outlier. Default mode is "and"' \
        , dest = 'mode', default = 'and')
    if len(sys.argv) == 1:
        parser.print_help()
        quit()
    args = parser.parse_args()

    check_args(args)
    get_deviants(args)
