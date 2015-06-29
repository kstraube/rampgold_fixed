#include "disassemble.h"
#include "opcodes.h"
#include "traps.h"
#include "decode.h"
#include <Common/sparcfpu.h>
#include <stdio.h>
#include <string.h>

char* disassemble(uint32_t insn, uint32_t PC, char buf[32])
{
  char buf2[32];
  char regltr[] = "goli";
  char reg[32][4];
  for(int i = 0; i < 32; i++)
  {
    reg[i][0] = '%';
    reg[i][1] = regltr[i/8];
    reg[i][2] = '0'+i%8;
    reg[i][3] = 0;
  }

  char bicc[16][16] = {"bn","be","ble","bl","bleu","bcs","bneg","bvs","ba","bne","bg","bge","bgu","bcc","bpos","bvc"};
  char fbfcc[16][16] = {"fbn","fbne","fblg","fbul","fbl","fbug","fbg","fbu","fba","fbe","fbue","fbge","fbuge","fble","fbule","fbo"};
  char cbccc[16][16] = {"cbn","cb123","cb12","cb13","cb1","cb23","cb2","cb3","cba","cb0","cb03","cb02","cb023","cb01","cb013","cb012"};
  char load[16][16] = {"ld","ldub","lduh","ldd"};
  char(*name)[16] = 0;

  char rs2_imm[16];
  if(HAS_IMMEDIATE)
    sprintf(rs2_imm,"%d",SIMM13);
  else
    strcpy(rs2_imm,reg[RS2]);

  char rs1_plus_rs2_imm[32];
  if(RS1)
  {
    if(HAS_IMMEDIATE && SIMM13 != 0)
      sprintf(rs1_plus_rs2_imm,"%s%+d",reg[RS1],SIMM13);
    else if(!HAS_IMMEDIATE && RS2)
      sprintf(rs1_plus_rs2_imm,"%s+%s",reg[RS1],reg[RS2]);
    else
      strcpy(rs1_plus_rs2_imm,reg[RS1]);
  }
  else strcpy(rs1_plus_rs2_imm,rs2_imm);

  char arith[16][16] = {"add","and","or","xor","sub","andn","orn","xnor","addx","","umul","smul","subx","","udiv","sdiv"};
  char arith2[16][16] = {"taddcc","tsubcc","taddcctv","tsubcctv","mulscc","sll","srl","sra"};
  switch(OP)
  {
    case 0:

      switch(OP2)
      {
        case 0:
          sprintf(buf,"unimp   0x%08x",IMM22);
          break;
        case 2: name = bicc;
        case 6: if(!name) name = fbfcc;
        case 7: if(!name) name = cbccc;
          strcpy(buf,name[COND]);
          if(ANNUL) strcat(buf,",a");
          for(int i = strlen(buf); i < 8; i++) strcat(buf," ");
          sprintf(buf2,"%d",4*DISP22);
          strcat(buf,buf2);
          break;
        case 4:
          if(RD == 0 && IMM22 == 0)
            strcpy(buf,"nop");
          else
            sprintf(buf,"sethi   0x%08x,%s",IMM22 << 10,reg[RD]);
          break;
        default:
          strcpy(buf,"unknown");
          break;
      }
      break;

    case 1:

      sprintf(buf,"call    0x%08x",PC+4*DISP30);
      break;

    case 2:
    {
      int cc = 1;

      switch(OP3 >> 3)
      {
        case 0:
        case 1: cc = 0;
        case 2:
        case 3: name = arith;
        case 4: if(!name) { name = arith2; cc = 0; }

          // lots of synthetic insns
          if(OP3 == 0x02 && RS1 == 0 && (!HAS_IMMEDIATE && RS2 == 0 || HAS_IMMEDIATE && SIMM13 == 0))
            sprintf(buf,"clr     %s",reg[RD]);
          else if(OP3 == 0x02 && RS1 == 0)
            sprintf(buf,"mov     %s,%s",rs2_imm,reg[RD]);
          else if(OP3 == 0x14 && RD == 0)
            sprintf(buf,"cmp     %s,%s",rs2_imm,reg[RS1]);
          else if(OP3 == 0x12 && RS1 == 0 && RD == 0)
            sprintf(buf,"tst     %s",rs2_imm);
          else if(OP3 == 0x12 && !HAS_IMMEDIATE && RS2 == 0 && RD == 0)
            sprintf(buf,"tst     %s",reg[RS1]);
          else if(OP3 == 0x11 && RD == 0)
            sprintf(buf,"btst    %s,%s",rs2_imm,reg[RS1]);
          else if(OP3 == 0x07 && !HAS_IMMEDIATE && RS2 == 0 && RS1 == RD)
            sprintf(buf,"not     %s",reg[RD]);
          else if(OP3 == 0x07 && !HAS_IMMEDIATE && RS2 == 0)
            sprintf(buf,"not     %s,%s",reg[RS1],reg[RD]);
          else if(OP3 == 0x04 && !HAS_IMMEDIATE && RS1 == 0 && RS1 == RD)
            sprintf(buf,"neg     %s",reg[RD]);
          else if(OP3 == 0x04 && !HAS_IMMEDIATE && RS1 == 0)
            sprintf(buf,"neg     %s,%s",reg[RS1],reg[RD]);
          else if(OP3 == 0x00 && HAS_IMMEDIATE && SIMM13 == 1 && RS1 == RD)
            sprintf(buf,"inc     %s",reg[RD]);
          else if(OP3 == 0x10 && HAS_IMMEDIATE && SIMM13 == 1 && RS1 == RD)
            sprintf(buf,"inccc   %s",reg[RD]);
          else if(OP3 == 0x04 && HAS_IMMEDIATE && SIMM13 == 1 && RS1 == RD)
            sprintf(buf,"dec     %s",reg[RD]);
          else if(OP3 == 0x14 && HAS_IMMEDIATE && SIMM13 == 1 && RS1 == RD)
            sprintf(buf,"deccc   %s",reg[RD]);
          else if(*name[OP3 & 0xf] == 0)
              strcpy(buf,"unknown");
          else
          {
            strcpy(buf,name[OP3 & 0xf]);
            if(cc) strcat(buf,"cc");
            for(int i = strlen(buf); i < 8; i++) strcat(buf," ");
            sprintf(buf2,"%s,%s,%s",reg[RS1],rs2_imm,reg[RD]);
            strcat(buf,buf2);
          }
          break;
        case 5:
          char src[8];
          if((OP3 & 0xf) == 8 && RS1 == 15 && RD == 0)
          {
            strcpy(buf,"stbar");
            break;
          }
          switch(OP3 & 0xf)
          {
            case 8:
              if(RS1 == 0)
                strcpy(src,"%y");
              else
                sprintf(src,"%%asr%d",RS1);
              break;
            case 9: strcpy(src,"%psr"); break;
            case 10: strcpy(src,"%wim"); break;
            case 11: strcpy(src,"%tbr"); break;
          }
          if(*src)
            sprintf(buf,"mov     %s,%s",src,reg[RD]);
          else
            strcpy(buf,"unknown");
          break;
        case 6:
        case 7:
          char dest[8] = "";
          switch(OP3 & 0xf)
          {
            case 0:
              if(RS1 == 0)
                strcpy(dest,"%y");
              else
                sprintf(dest,"%%asr%d",RS1);
              break;
            case 1: strcpy(dest,"%psr"); break;
            case 2: strcpy(dest,"%wim"); break;
            case 3: strcpy(dest,"%tbr"); break;
          }
          if(*dest)
          {
            if(RS1 == 0)
              sprintf(buf,"mov     %s,%s",rs2_imm,dest);
            else if(!HAS_IMMEDIATE && RS2 == 0 || HAS_IMMEDIATE && SIMM13 == 0)
              sprintf(buf,"mov     %s,%s",reg[RS1],dest);
            else
              sprintf(buf,"xor     %s,%s,%s",reg[RS1],rs2_imm,dest);
            break;
          }
          fp_insn_t fpi = *(fp_insn_t*)&insn;

          switch(OP3 & 0xf)
          {
            case 4:
            case 5:
              strcpy(buf,"fp");
              break;
            case 6:
            case 7:
              sprintf(buf,"cpop%d   0x%03x,%%creg%d,%%creg%d,%%creg%d",1+(OP3&1),fpi.opf,fpi.rs1,fpi.rs2,fpi.rd);
              break;
            case 8:
              if(RD == 0)
                sprintf(buf,"jmp     %s",rs1_plus_rs2_imm);
              else if(RD == 15)
                sprintf(buf,"call    %s",rs1_plus_rs2_imm);
              else
                sprintf(buf,"jmpl    %s,%s",rs1_plus_rs2_imm,reg[RD]);
              break;
            case 9:
              sprintf(buf,"rett    %s",rs1_plus_rs2_imm);
              break;
            case 10:
              strcpy(buf,bicc[COND & 0xf]);
              buf[0] = 't';
              for(int i = strlen(buf); i < 8; i++) strcat(buf," ");
              strcat(buf,rs1_plus_rs2_imm);
              break;
            case 11:
              sprintf(buf,"flush   %s",rs1_plus_rs2_imm);
              break;
            case 12:
              if(RS1 == 0 && (HAS_IMMEDIATE && RS2 == 0 || !HAS_IMMEDIATE && SIMM13 == 0))
                strcpy(buf,"save");
              else
                sprintf(buf,"save    %s,%s,%s",reg[RS1],rs2_imm,reg[RD]);
              break;
            case 13:
              if(RS1 == 0 && (HAS_IMMEDIATE && RS2 == 0 || !HAS_IMMEDIATE && SIMM13 == 0))
                strcpy(buf,"restore");
              else
                sprintf(buf,"restore %s,%s,%s",reg[RS1],rs2_imm,reg[RD]);
              break;
            default:
              strcpy(buf,"unknown");
          }
          break;
      }
    }
    break;

    case 3:
    {
      char fc = (OP3 & 0x10) ? 'c' : 'f';

      if((OP3 & ~0x10) == 0x20)
        sprintf(buf,"ld%c     [%s],%s",fc,rs1_plus_rs2_imm,reg[RD]);
      else if((OP3 & ~0x10) == 0x21)
        sprintf(buf,"ld%csr   [%s],%s",fc,rs1_plus_rs2_imm,reg[RD]);
      else if((OP3 & ~0x10) == 0x23)
        sprintf(buf,"ldd%c    [%s],%s",fc,rs1_plus_rs2_imm,reg[RD]);
      else if((OP3 & ~0x10) == 0x24)
        sprintf(buf,"st%c     %s,[%s]",fc,reg[RD],rs1_plus_rs2_imm);
      else if((OP3 & ~0x10) == 0x25)
        sprintf(buf,"st%csr   %s,[%s]",fc,reg[RD],rs1_plus_rs2_imm);
      else if((OP3 & ~0x10) == 0x26)
        sprintf(buf,"std%cq   %s,[%s]",fc,reg[RD],rs1_plus_rs2_imm);
      else if((OP3 & ~0x10) == 0x27)
        sprintf(buf,"std%c    %s,[%s]",fc,reg[RD],rs1_plus_rs2_imm);
      else if((OP3 & ~0x10) & 0x20)
        strcpy(buf,"unknown");
      else
      {
        if((OP3 & 0xf) == 0x9)
          strcpy(buf2,"ldsb");
        else if((OP3 & 0xf) == 0xa)
          strcpy(buf2,"ldsh");
        else if((OP3 & 0xf) == 0xd)
          strcpy(buf2,"ldstub");
        else if((OP3 & 0xf) == 0xf)
          strcpy(buf2,"swap");
        else if(OP3 & 0x8)
        {
          strcpy(buf2,"unknown");
          break;
        }
        else
        {
          strcpy(buf2,load[OP3 & 0x3]);
          if(OP3 & 0x4)
            memcpy(buf2,"st",2);
        }
        if(OP3 & 0x10)
          strcat(buf2,"a");
        for(int i = strlen(buf2); i < 8; i++) strcat(buf2," ");

        switch(OP3 & 0x1c)
        {
          case 0x00:
          case 0x08:
          case 0x0c:
            sprintf(buf,"%s[%s],%s",buf2,rs1_plus_rs2_imm,reg[RD]);
            break;
          case 0x04:
            sprintf(buf,"%s%s,[%s]",buf2,reg[RD],rs1_plus_rs2_imm);
            break;
          case 0x10:
          case 0x18:
          case 0x1c:
            sprintf(buf,"%s[%s] %d,%s",buf2,rs1_plus_rs2_imm,ASI,reg[RD]);
            break;
          case 0x14:
            sprintf(buf,"%s%s,[%s] %d",buf2,reg[RD],rs1_plus_rs2_imm,ASI);
            break;
        }
      }

      break;
    }
  }

  return buf;
}
