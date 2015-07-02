# rampgold_fixed
fixed up version of RAMP Gold architecture simulator with updated akaros

to simulate:
go to sparcmt/project_files/simulation/top_1P_bee3_neweth/
open the mpf file with modelsim and simulate

to synthesize:
then go to sparcmt/project_files/synthesis/top_1P_bee3_neweth/
open the synplify project file there and run synth and p&r
then go to sparcmt/project_files/synthesis/top_1P_bee3_neweth/rev_1/par_1
and run bitgen fpga_top.ncd outputfile.bit
now you have a bit file to put on the FPGA!
This requires synplify and the xilinx ide
The current implementation runs on the Xilinx XUP board

to build akaros:
go to the akaros folder and run make

To run:
load the fpga with the bitfile
go to the appserver folder for the version you are using (naming changes slightly)
then go to /build/bin
run ./sparc_app -s -p"NUMBER OF PROCESSORS HERE" -f appserver_ros.conf hw ~/(path to akaros-latest)/obj/kern/kernel none
the conf file may need to be edited to match your pc setup

the FPGA and PC need to be connected by an ethernet cable

Notes about the implementation changes to get RAMP Gold working:

%all the work that we did to get RAMP Gold up and running
HySIM is based on the RAMP Gold simulator architecture, so the first step to
creating HySIM was to get the RAMP Gold simulator running. We did not expect
this to take much time or be very difficult - unfortunately, we were sadly
mistaken.  Getting RAMP Gold running proved to be an enormous task, requiring 
multiple code fixes before RAMP Gold would function properly. Many of these 
issues could be traced back to the non-standard Akaros operating system that is 
used in RAMP Gold.

%The Akaros operating system provided many issues with the installation of the 
%RAMP Gold simulator. 
For example, the latest version of Akaros no longer supports the 
RAMP Gold architecture. This is not immediately obvious, because the RAMP Gold 
website points to the Akaros website without any mention of a specific version 
requirement. Using some date and version investigation, we finally tracked down 
the correct version of Akaros. Unfortunately, this version does not
benefit from any improvements or refinements to Akaros, because Akaros support 
for SPARC (which is the processor that RAMP Gold emulates) was dropped in favor 
of RISC-V on May 9, 2011. This means that many of the improvements and bug 
fixes are not included in the version required for RAMP Gold.

Once the correct operating system was obtained, the issue of getting meaningful 
benchmarks running on the system still remained. As we attempted to run 
different benchmarks on the system, we discovered that Akaros lacked proper 
Pthread library support. The Pthread library is a key resource for running 
many multi-threaded applications. Basic Pthread support in Akaros exists, but 
it was incomplete for the SPARC target system. This resulted in even simple test
programs failing with related Pthread errors. One of the main errors was 
related to the thread scheduler not properly detecting when all of the cores 
were idle before returning to the shell. We modified the 
\texttt{\_\_smp\_idle()} function to periodically check whether there were 
threads running on other cores before returning to the management shell, and 
only returned to the shell when all cores were idle for a specified duration. 
This is a clear workaround instead of a permanent fix, but due to the 
complicated nature of the operating system thread scheduler, we could not 
provide a permanent fix.

Another key issue with Akaros was a bug in the filesystem code. This bug caused 
a memory access exception during execution, but not during FPGA simulation. 
%CHRIS: I added FPGA simulation. We are talking about the bug occuring during system execution, but not FPGA emulation, right? Yes
%After some investigation, 
We eventually tracked this problem down to a bug (an uninitialized variable 
\texttt{k\_i\_info->init\_size}) in the file system code. This bug does not 
occur in the functional simulator because the memory is initialized to zero in 
the simulator, but does on the FPGA hardware, where the memory contains random 
values that may not be properly initialized. By properly initializing the
\texttt{k\_i\_info->init\_size} variable, the system successfully accessed 
memory.

On the hardware side, the constraints mapping proved to cause some
challenges with a slightly more complicated tool flow. The codebase for RAMP Gold
is written in SystemVerilog. The Xilinx ISE cannot synthesize SystemVerilog so
Synplify Premier was used. The challenge came from mapping the constraints
for any new designs generated from the Xilinx Core Generator into the
pre-existing design. The Xilinx ISE and Core Generator use user constraint
files (.ucf extension) to define the constraints for a given design. The 
Synplify tools use a table based approach called synplify design constraints
(.sdc extension). The naming conventions between the two file types also
change. In particular, the auto-generated blocks from generate loops
within a design are named differently by each of the two tools.
Transferring the constraints required some research and
trial and error. Ultimately, the location constraints belonged in the
attributes tab of the synplify design constraints file.
This accounted for most of the relevant constraint that had to be transferred.

%We run MCF, bzip2 and facesim
Eventually, however, we were able to run several PARSEC benchmarks on the RAMP Gold
infrastructure, so we are now able to move on to the creation of HySIM.

