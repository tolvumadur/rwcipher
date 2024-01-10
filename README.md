# rwcipher
Read and write encrypted files in go

This module performs encryption and decryption in RAM, meaning there are performance consequences (i.e. swapping) if you encrypt/decrypt a file larger than you have available RAM. If performing multple encryptions concurrently, consider the cumulative memory usage to avoid OOM panics.