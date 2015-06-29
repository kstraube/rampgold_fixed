#----------------------------------------------------------------------
# Makefile to run adpcm program
#----------------------------------------------------------------------

default : all

KERNEL_SCALEBIN = ../../../ProxyKernel/kernel.ramp
ALL_SCALEBIN = ../src/rawdcaudio
SIMULATOR = ../../../TestAppServer/build/sparcfs_app $(KERNEL_SCALEBIN)

decode_output_ref = output_ref.pcm
decode_output_tst = output_tst.pcm

encode_output_ref = output_ref.adpcm
encode_output_tst = output_tst.adpcm

run-dc : $(decode_output_tst) $(encode_output_tst)
$(decode_output_tst) :
	$(SIMULATOR) $(ALL_SCALEBIN) \
	diff $(decode_output_tst) $(decode_output_ref) \
	diff $(encode_output_tst) $(encode_output_ref)

all : run-dc

clean:
	rm -rf $(decode_output_tst) $(encode_output_tst) *~
