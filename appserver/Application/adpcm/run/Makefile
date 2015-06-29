#----------------------------------------------------------------------
# Makefile to run adpcm program
#----------------------------------------------------------------------

default : all

KERNEL_SCALEBIN = ../../../ProxyKernel/kernel.ramp
DECODE_SCALEBIN = ../src/rawdaudio
ENCODE_SCALEBIN = ../src/rawcaudio
SIMULATOR = ../../../TestAppServer/build/sparcfs_app $(KERNEL_SCALEBIN)

decode_input      = input.adpcm
decode_output_ref = output_ref.pcm
decode_output_tst = output_tst.pcm

run-decode : $(decode_output_tst)
$(decode_output_tst) :
	$(SIMULATOR) $(DECODE_SCALEBIN) < $(decode_input) > $@; \
	diff $@ $(decode_output_ref)

encode_input      = input.pcm
encode_output_ref = output_ref.adpcm
encode_output_tst = output_tst.adpcm

run-encode : $(encode_output_tst)
$(encode_output_tst) :
	$(SIMULATOR) $(ENCODE_SCALEBIN) < $(encode_input) > $@; \
	diff $@ $(encode_output_ref)

all : run-decode run-encode

clean:
	rm -rf $(decode_output_tst) $(encode_output_tst) *~
