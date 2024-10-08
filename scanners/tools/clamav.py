import clamd

def run_clamav_fs_scan(file_path):
    # Run ClamAV scan on the file system.
    cd = clamd.ClamdUnixSocket()  # Or ClamdNetworkSocket() depending on configuration
    scan_result = cd.multiscan(file_path)
    return scan_result
