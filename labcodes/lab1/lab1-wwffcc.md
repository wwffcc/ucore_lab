# Lab1 Report

## [练习1]
[练习1.1] 
1.操作系统镜像文件 ucore.img 是如何一步一步生成的?(需要比较详细地解释 Makefile 中每一条相关命令和命令参数的含义,以及说明命令导致的结果)
>
```
通过make --just-print可以看到make对Makefile中语句的执行流程，其中的宏也被替换为运行中的变量名。
在Makefile中的
| # create ucore.img
|   UCOREIMG	:= $(call totarget,ucore.img)
|
|   $(UCOREIMG): $(kernel) $(bootblock)
|	    $(V)dd if=/dev/zero of=$@ count=10000
|	    $(V)dd if=$(bootblock) of=$@ conv=notrunc
|	    $(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc
|
|   $(call create_target,ucore.img)
是关于ucore.img的创建，其中$@是自动变量，引用了UCOREIMG，通过调用totarget函数，运行过程中UCOREIMG扩展成为bin/ucore.img,其中dd是复制并转换文件，if指的是读取的文件，of指的是写入的文件，count指示copy的大小，conv=notrunc指示不要删节。总之，这些命令负责了ucore.img的生成。这里UCOREIMG的依赖文件是kernel，bookblock，所以之前要生成kernel，bootblock。
|
|对于bootblock，其生成为
|   |$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
|	|   @echo + ld $@
|   |   $(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
|	|   @$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
|	|   @$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
|	|   @$(call totarget,sign) $(call outfile,bootblock) $(bootblock)
|   |
|   |这里$@是boot/bootasm.S，boot/bootmain.c，tools/sign.c，依次会编译生成obj/boot/ bootasm.o,obj/boot/bootmain.o,bin/sign,而bootblock也正依赖于这三个文件。
|   |
|   |先说明bootasm.o和bootmain.o的生成。
|   |   |语句如下：
|   |   |bootfiles = $(call listf_cc,boot)
|   |   |$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))
|   |   |这里的编译都是通过宏在运行make过程中完成的。
|   |   |其中生成bootasm.o是通过编译bootasm.S汇编文件，在make --just-print下，看到展开为：
|   |   |gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootasm.S -o obj/boot/bootasm.o
|   |   |这些参数都是编译的选项，解释如下(参考了答案的解释)
|	|	| 	-ggdb  生成可供gdb使用的调试信息。这样才能用qemu+gdb来调试bootloader or ucore。
|	|	|	-m32  生成适用于32位环境的代码。我们用的模拟硬件是32bit的80386，所以ucore也要是32位的软件。
|	|	| 	-gstabs  生成stabs格式的调试信息。这样要ucore的monitor可以显示出便于开发者阅读的函数调用栈信息
|	|	| 	-nostdinc  不使用标准库。标准库是给应用程序用的，我们是编译ucore内核，OS内核是提供服务的，所以所有的服务要自给自足。
|	|	|	-fno-stack-protector  不生成用于检测缓冲区溢出的代码。这是for 应用程序的，我们是编译内核，ucore内核好像还用不到此功能。
|	|	| 	-Os  为减小代码大小而进行优化。根据硬件spec，主引导扇区只有512字节，我们写的简单bootloader的最终大小不能大于510字节。
|	|	| 	-I<dir>  添加搜索头文件的路径
|	|	| 	-fno-builtin  除非用__builtin_前缀，
|	|	|	              否则不进行builtin函数的优化
|   |   |而生成bootmain.o的语句是类似的，只不过替换了文件名：
|   |   |gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootmain.c -o obj/boot/bootmain.o
|   |
|   |   |关于bin/sign的生成
|   |   |# create 'sign' tools
|   |   |$(call add_files_host,tools/sign.c,sign,sign)
|   |   |$(call create_target_host,sign,sign)
|   |   |实际将宏扩展开来是
|   |   |gcc -Itools/ -g -Wall -O2 -c tools/sign.c -o obj/sign/tools/sign.o
gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
|   |   |
|   |然后生成bootblock.o
|   |ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
|   |其中的选项解释如下：
|   |   -m  elf_i386:是模拟intel386的模拟器
|   |   -nostdlib:不使用标准库
|   |   -N：设置代码段和数据段均可读写
|   |   -e start：指定入口
|   |   -Ttext:代码段的开始位置为0x7C00
|   |
|   |将bootblock.o的代码反汇编后输出到bootblock.asm
|   |   objdump -S obj/bootblock.o > obj/bootblock.asm
|   |   其中-S:移除所有符号和重定位信息
|   |
|   |将二进制代码bootblock.o复制到bootblock.out
|   |   objcopy -S -O binary obj/bootblock.o obj/bootblock.out
|   |   其中-O binary：指定输出格式为二进制文件
|
|有关bin/kernel的生成
|   |$(kernel): tools/kernel.ld
|   |$(kernel): $(KOBJS)
|   |@echo + ld $@
|   |$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
|   |@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
|   |@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)
|   |实际的那段链接代码$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)展开为：
|   |ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel  obj/kern/init/init.o obj/kern/libs/readline.o obj/kern/libs/stdio.o obj/kern/debug/kdebug.o obj/kern/debug/kmonitor.o obj/kern/debug/panic.o obj/kern/driver/clock.o obj/kern/driver/console.o obj/kern/driver/intr.o obj/kern/driver/picirq.o obj/kern/trap/trap.o obj/kern/trap/trapentry.o obj/kern/trap/vectors.o obj/kern/mm/pmm.o  obj/libs/printfmt.o obj/libs/string.o
|   |其中，关键字-T <scriptfile>  让连接器使用指定的脚本
|   |为此，首先要生成相关依赖文件KOBJS(tools/kernel.ld已经存在)
|   |
|   |关于obj/kern/*/*.o的生成
|   | $(call add_files_cc,$(call listf_cc,$(KSRCDIR)),kernel,$(KCFLAGS))
|   |举一个例子obj/kern/init/init.o
|   |其实际代码为：
|   |gcc -Ikern/init/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/init/init.c -o obj/kern/init/init.o
|
|最终的结果是(参考了答案的解释)
| 生成一个有10000个块的文件，每个块默认512字节，用0填充
| dd if=/dev/zero of=bin/ucore.img count=10000
|
| 把bootblock中的内容写到第一个块
| dd if=bin/bootblock of=bin/ucore.img conv=notrunc
|
| 从第二个块开始写kernel中的内容
```

[练习1.2] 一个被系统认为是符合规范的硬盘主引导扇区的特征是什么? 
>
由Makefile的执行代码bin/sign obj/bootblock.out bin/bootblock，可见是sign起到将bootblock.out写到主引导扇区的作用。  
由sign.c，可以看到  
一个硬盘主引导扇区的大小是512字节；  
第510个（倒数第二个）字节是0x55，  
第511个（倒数第一个）字节是0xAA。

## [练习2]

[练习2.1] 从 CPU 加电后执行的第一条指令开始,单步跟踪 BIOS 的执行。

>修改tools/gdbinit为 
```
set architecture i8086
target remote :1234
```
运行make debug，此时看到%eip=0xfff0.
我一直都试图用x/2i $eip查看该处的汇编代码，但总是不对，和提示中给的不一样。
用p $cs看到cs=0xf000。我想到现在应该处于实模式，应该把cs和%eip的值连起来看，因而执行的指令实际是0xffff0,于是用x/2i 0xfff0，看到了长跳转指令。随后，通过单步跟踪，查看了BIOS的执行，发现在0xfd155（此时%eip=0xd155）执行完后，%eip的值变为0xfd15d,可以直接用x/2i $eip查看汇编代码。


[练习2.2] 在初始化位置0x7c00 设置实地址断点,测试断点正常。

将tools/gdbinit修改为
```
file bin/kernel
target remote :1234
set architecture i8086
b *0x7c00
c
x /20i $pc
set architecture i386
```
最后看到的20条指令如下
```
   0x7c00:	cli
   0x7c01:	cld
   0x7c02:	xor    %eax,%eax
   0x7c04:	mov    %eax,%ds
   0x7c06:	mov    %eax,%es
   0x7c08:	mov    %eax,%ss
   0x7c0a:	in     $0x64,%al
   0x7c0c:	test   $0x2,%al
   0x7c0e:	jne    0x7c0a
   0x7c10:	mov    $0xd1,%al
   0x7c12:	out    %al,$0x64
   0x7c14:	in     $0x64,%al
   0x7c16:	test   $0x2,%al
   0x7c18:	jne    0x7c14
   0x7c1a:	mov    $0xdf,%al
   0x7c1c:	out    %al,$0x60
   0x7c1e:	lgdtl  (%esi)
   0x7c21:	insb   (%dx),%es:(%edi)
   0x7c22:	jl     0x7c33
   0x7c24:	and    %al,%al
```
和boot/bootasm.S内的代码是一致的。断点没有问题。


[练习2.3] 在调用qemu 时增加-d in_asm -D q.log 参数，便可以将运行的汇编指令保存在q.log 中。
将执行的汇编代码与bootasm.S 和 bootblock.asm 进行比较，看看二者是否一致。

> 修改tools/gdbinit如下：
```
    file bin/kernel
    target remote :1234
    set architecture i8086  
    b *0x7c00
    c
    x /20i $pc
    set architecture i386  
```
所得到的汇编代码为：
```
    ----------------
    IN: 
    0x00007c00:  cli    
    0x00007c01:  cld    
    0x00007c02:  xor    %ax,%ax
    0x00007c04:  mov    %ax,%ds
    0x00007c06:  mov    %ax,%es
    0x00007c08:  mov    %ax,%ss

    ----------------
    IN: 
    0x00007c0a:  in     $0x64,%al

    ----------------
    IN: 
    0x00007c0c:  test   $0x2,%al
    0x00007c0e:  jne    0x7c0a

    ----------------
    IN: 
    0x00007c10:  mov    $0xd1,%al
    0x00007c12:  out    %al,$0x64
    0x00007c14:  in     $0x64,%al
    0x00007c16:  test   $0x2,%al
    0x00007c18:  jne    0x7c14

    ----------------
    IN: 
    0x00007c1a:  mov    $0xdf,%al
    0x00007c1c:  out    %al,$0x60
    0x00007c1e:  lgdtw  0x7c6c
    0x00007c23:  mov    %cr0,%eax
    0x00007c26:  or     $0x1,%eax
    0x00007c2a:  mov    %eax,%cr0

    ----------------
    IN: 
    0x00007c2d:  ljmp   $0x8,$0x7c32

    ----------------
    IN: 
    0x00007c32:  mov    $0x10,%ax
    0x00007c36:  mov    %eax,%ds

    ----------------
    IN: 
    0x00007c38:  mov    %eax,%es

    ----------------
    IN: 
    0x00007c3a:  mov    %eax,%fs
    0x00007c3c:  mov    %eax,%gs
    0x00007c3e:  mov    %eax,%ss

    ----------------
    IN: 
    0x00007c40:  mov    $0x0,%ebp

    ----------------
    IN: 
    0x00007c45:  mov    $0x7c00,%esp
    0x00007c4a:  call   0x7cd1

    ----------------
    IN: 
    0x00007cd1:  push   %ebp
```
其与bootasm.S和bootblock.asm中的代码相同。


[练习2.4] 自己找一个bootloader或内核的代码位置，设置断点并进行测试。

>
在bootmain函数的路口设置断点，由bin/q.log可以看到实际的代码：
```
    IN: 
    0x00007cd1:  push   %ebp
    0x00007cd2:  mov    %esp,%ebp
    0x00007cd4:  push   %edi
    0x00007cd5:  push   %esi
    0x00007cd6:  push   %ebx
    0x00007cd7:  mov    $0x1,%ebx
    0x00007cdc:  sub    $0x1c,%esp
    0x00007cdf:  lea    0x7f(%ebx),%eax
    0x00007ce2:  mov    %ebx,%edx
    0x00007ce4:  shl    $0x9,%eax
    0x00007ce7:  inc    %ebx
    0x00007ce8:  call   0x7c72
```
又由bootblock.asm或者由obj/boot/bootmain.o反汇编可以看到，两个代码是一致的。


## [练习3]
分析bootloader 进入保护模式的过程。

> 从`%cs=0 $pc=0x7c00`，进入后,
首先清理寄存器
```
    .code16
	    cli
	    cld
	    xorw %ax, %ax
	    movw %ax, %ds
	    movw %ax, %es
	    movw %ax, %ss
```
然后是使能A20 gate。之所以要开启A20,是因为为了访问高地址，必须打开，否则即便在保护模式下，也只能访问奇数兆的内存地址。而为了开启A20,必须通过IO操作，向键盘控制器8042发送一个命令，然后8042会将它的某个输出引脚的输出置为高电平，作为A20地址控制线的输入。具体操作是通过向端口64h发送命令，在60h读写完成的。整个开启的步骤为：
```
    1.等待8042的Input Buffer为空
    2.发送Write 8042 Output Buffer(P2)命令到8042 Input Buffer
    3.等待8042的Input Buffer为空
    4.将8042 Output Port(P2)得到字节的第2位置1,然后写入8042 Input Bufffer
```
在bootasm.S中的实现为：
```
    seta20.1:
         30     inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
         31     testb $0x2, %al
         32     jnz seta20.1
         33 
         34     movb $0xd1, %al                                 # 0xd1 -> port 0x64
         35     outb %al, $0x64                                 # 0xd1 means: write data to 8042's P2 port
         36 
         37 seta20.2:
         38     inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
         39     testb $0x2, %al
         40     jnz seta20.2
         41 
         42     movb $0xdf, %al                                 # 0xdf -> port 0x60
         43     outb %al, $0x60                                 # 0xdf = 11011111, means set P2's A20 bit(the 1      43 bit) to 1
```
初始化GDT表：一个简单的GDT表和其描述符已经静态储存在引导区中，载入即可
```
	    lgdt gdtdesc
```
进入保护模式：通过将cr0寄存器PE位置1便开启了保护模式
```
	    movl %cr0, %eax
	    orl $CR0_PE_ON, %eax
	    movl %eax, %cr0
```

由于cs的值不能通过move重写，因此采用长跳转更新cs的基地址
```
	 ljmp $PROT_MODE_CSEG, $protcseg
	.code32
	protcseg:
```

设置段寄存器，并建立堆栈，该帧的范围是0x0000~0x7c00
```
	    movw $PROT_MODE_DSEG, %ax
	    movw %ax, %ds
	    movw %ax, %es
	    movw %ax, %fs
	    movw %ax, %gs
	    movw %ax, %ss
	    movl $0x0, %ebp
	    movl $start, %esp
```

现在，转到保护模式完成，进入boot主方法
```
	    call bootmain
```

## [练习4]
分析bootloader加载ELF格式的OS的过程。

> 主要有三个函数：  

首先看readsect函数，
`readsect`从设备的第secno扇区读取数据到dst位置
```
	static void
	readsect(void *dst, uint32_t secno) {
	    waitdisk();                  //等待disk处于就绪状态
	
	    outb(0x1F2, 1);                         // 设置读取扇区的数目为1
	    outb(0x1F3, secno & 0xFF);
	    outb(0x1F4, (secno >> 8) & 0xFF);
	    outb(0x1F5, (secno >> 16) & 0xFF);
	    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);  //28位为0,表示访问“disk 0"，29-31位为1
	        // 上面四条指令联合制定了扇区号
	        // 在这4个字节线联合构成的32位参数中
	        //   29-31位强制设为1
	        //   28位(=0)表示访问"Disk 0"
	        //   0-27位是28位的偏移量
	    outb(0x1F7, 0x20);                      // 0x20命令，读取扇区
	
	    waitdisk();

	    insl(0x1F0, dst, SECTSIZE / 4);         // 读取到dst位置，
	                                            // 幻数4因为这里以DW为单位
	}
```

readseg简单包装了readsect，可以从设备读取任意长度的内容。
```
	static void
	readseg(uintptr_t va, uint32_t count, uint32_t offset) {
	    uintptr_t end_va = va + count;
	    
	    va -= offset % SECTSIZE;    //让va以扇区大小对齐
	   
	    uint32_t secno = (offset / SECTSIZE) + 1; //转化为扇区号；kernel从1号扇区开始
	    // 加1因为0扇区被引导占用
	    // ELF文件从1扇区开始
	
	    for (; va < end_va; va += SECTSIZE, secno ++) {
	        readsect((void *)va, secno);
	    }
	}
```

在bootmain函数中，
```
	void
	bootmain(void) {
	    // 首先读取ELF的头部
	    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);
	
	    // 通过储存在头部的幻数判断是否是合法的ELF文件
	    if (ELFHDR->e_magic != ELF_MAGIC) {
	        goto bad;
	    }
	
	    struct proghdr *ph, *eph;
	
	    // ELF头部有描述ELF文件应加载到内存什么位置的描述表，
	    // 先将描述表的头地址存在ph
	    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
	    eph = ph + ELFHDR->e_phnum;
	
	    // 按照描述表将ELF文件中数据载入内存
	    for (; ph < eph; ph ++) {
	        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
	    }
	    // ELF文件0x1000位置后面的0xd1ec比特被载入内存0x00100000
	    // ELF文件0xf000位置后面的0x1d20比特被载入内存0x0010e000

	    // 根据ELF头部储存的入口信息，找到内核的入口
	    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
	
	bad:
	    outw(0x8A00, 0x8A00);
	    outw(0x8A00, 0x8E00);
	    while (1);
	}
```

可见bootloader读取硬盘扇区最基本的是靠readsect实现的，通过CPU访问硬盘的IO地址寄存器，设置相应的字段来实现对硬盘读的控制。大致流程是：
```
    1.等待磁盘准备好
    2.发出读取扇区的命令
    3.等待磁盘准备好
    4.把磁盘扇区数据读到指定内存
```

bootloader加载ELF格式的OS方法是：
```
    1.查看ELF文件是否valid
    2.从头部elfhdr抽取描述表，载入指定内存
    3.跳转至内核入口，准备将控制权转交OS
```


## [练习5] 
实现函数调用堆栈跟踪函数 

>
ss:ebp指向的堆栈位置储存着caller的ebp，以此为线索可以得到所有使用堆栈的函数ebp。
ss:ebp+4指向caller调用时的eip，ss:ebp+8等是（可能的）参数。

输出中，堆栈最深一层为
```
	ebp:0x00007bf8 eip:0x00007d68 args:0xc031fcfa 0xc08ed88e 0x64e4d08e 0xfa7502a8 \ 
        <unknow>: -- 0x00007d67 --
```

其对应的是第一个使用堆栈的函数，即bootmain.c中的bootmain。
bootloader设置的堆栈从0x7c00开始，使用"call bootmain"转入bootmain函数。
call指令压栈，所以bootmain中ebp为0x7bf8。


##[练习6]完善中断初始化和处理 （需要编程）

[练习6.1] 中断向量表中一个表项占多少字节？其中哪几位代表中断处理代码的入口？

> 查看kern/mm/mmu.h的门结构
struct gatedesc {
    unsigned gd_off_15_0 : 16;        // low 16 bits of offset in segment
    unsigned gd_ss : 16;            // segment selector
    unsigned gd_args : 5;            // # args, 0 for interrupt/trap gates
    unsigned gd_rsv1 : 3;            // reserved(should be zero I guess)
    unsigned gd_type : 4;            // type(STS_{TG,IG32,TG32})
    unsigned gd_s : 1;                // must be 0 (system)
    unsigned gd_dpl : 2;            // descriptor(meaning new) privilege level
    unsigned gd_p : 1;                // Present
    unsigned gd_off_31_16 : 16;        // high bits of offset in segment
};
而kern/trap/trap.c中对中断向量表idt的定义为：
static struct gatedesc idt[256] = {{0}};
可见idt中一个表项占64个bit，即8个字节。</br>
其中2-3字节是段选择子，6-7字节和0-1字节拼在一起形成偏置，两者联合便是中断处理程序的入口地址。

[练习6.2] 请编程完善kern/trap/trap.c中对中断向量表进行初始化的函数idt_init。

>根据注释的提示编写idt_init的代码。先将idt的表项的段描述符的DPL都置为特权0,但其中提供了一个表项idt[T_SWITCH_TOK]的DPL为3,这样可以通过这个表项实现陷入。然后使用lidt指令，将中断向量表通知给CPU。

[练习6.3] 请编程完善trap.c中的中断处理函数trap，在对时钟中断进行处理的部分填写trap函数

> 在trap_dispatch的时钟中断处理例程中，按照每100个ticks打印一次ticks，简单调用print_ticks即可。


## [扩展练习]Challenge 1
增加syscall功能，即增加一用户态函数（可执行一特定系统调用：获得时钟计数值），
当内核初始完毕后，可从内核态返回到用户态的函数，而用户态的函数又通过系统调用得到内核态的服务

>
在idt_init中，将用户态调用SWITCH_TOK中断的权限打开。
	SETGATE(idt[T_SWITCH_TOK], 1, KERNEL_CS, __vectors[T_SWITCH_TOK], 3);

在trap_dispatch中，将iret时会从堆栈弹出的段寄存器进行修改
	对TO User
```
	    tf->tf_cs = USER_CS;
	    tf->tf_ds = USER_DS;
	    tf->tf_es = USER_DS;
	    tf->tf_ss = USER_DS;
```
	对TO Kernel

```
	    tf->tf_cs = KERNEL_CS;
	    tf->tf_ds = KERNEL_DS;
	    tf->tf_es = KERNEL_DS;
```

在lab1_switch_to_user中，调用T_SWITCH_TOU中断。
注意从中断返回时，会多pop两位，并用这两位的值更新ss,sp，损坏堆栈。
所以要先把栈压两位，并在从中断返回后修复esp。
```
	asm volatile (
	    "sub $0x8, %%esp \n"
	    "int %0 \n"
	    "movl %%ebp, %%esp"
	    : 
	    : "i"(T_SWITCH_TOU)
	);
```

在lab1_switch_to_kernel中，调用T_SWITCH_TOK中断。
注意从中断返回时，esp仍在TSS指示的堆栈中。所以要在从中断返回后修复esp。
```
	asm volatile (
	    "int %0 \n"
	    "movl %%ebp, %%esp \n"
	    : 
	    : "i"(T_SWITCH_TOK)
	);
```

但这样不能正常输出文本。根据提示，在trap_dispatch中转User态时，将调用io所需权限降低。
```
	tf->tf_eflags |= 0x3000;
```
