# KUlele

exploit của a Biên nhưng có thêm comment.

note: `tty_struct` alloc với `GFP_KERNEL_ACCOUNT` nhưng `tty_file_private` vẫn alloc với `GFP_KERNEL`, ref: [link](https://github.com/smallkirby/kernelpwn/blob/master/technique/tty_struct.md)