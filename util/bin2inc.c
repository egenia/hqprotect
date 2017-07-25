#include <stdio.h>
#include <stdlib.h>
#include <io.h>

FILE    *infile,*outfile;

void    main(int argc,char **argv)
        {
        int     fsize,i,line=0;
        unsigned int cc;

        if (argc!=4) {
           printf("Error in parameters\r\n\r\nUse : bin2inc.exe <infile> <outfile> <ID>\r\n");
           exit(1);
           }
        infile=fopen(argv[1],"rb");
        fsize=filelength(fileno(infile));
        outfile=fopen(argv[2],"wb");

        cc=fgetc(infile);
        fprintf(outfile,"; <%s> data file, converted to .INC by bin2inc.exe (c) E-genia\r\n; File size : %d\r\n",argv[1],fsize);

        for (i=0;i<strlen(argv[3]);i++) {
            if (argv[3][i]>=48&&argv[3][i]<=57) {}
               else
            if (argv[3][i]>=65&&argv[3][i]<=90) {}
               else
            if (argv[3][i]>=97&&argv[3][i]<=122) {}
               else
               argv[3][i]='_';
            }
        fprintf(outfile,"\r\nFD_%s_len  equ     %d\r\n",argv[3],fsize);
        fprintf(outfile,"\r\nFD_%s_start:\r\n",argv[3]);
        while (cc!=EOF) {
              if (line==0) {
                 fprintf(outfile,"\r\ndb     ");
                 }
              fprintf(outfile,"%#03d",cc);
              line++;
              cc=fgetc(infile);
              if (line>10) line=0;
                 else
                 if (cc!=EOF)
                    fprintf(outfile,", ");
                    else
                    fprintf(outfile,"\r\n");
              }
        fprintf(outfile,"\r\nFD_%s_end:\r\n",argv[3]);
        fcloseall();
        }
