# Android-Mem-Edit
基于Linux内核，安卓应用进程，内存修改工具

主要思路流程：

1.根据/ proc / pid / maps文件获取到相应的pid的内存页的分配

2.使用读取内存页的开始地址

3.利用pread / pwrite进行内存地址的读取和修改

4.linux内核中采用的是虚拟内存进行映射（类似django中的数据库映射）ORM。
