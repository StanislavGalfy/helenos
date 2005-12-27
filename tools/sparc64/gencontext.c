#include <stdio.h>

typedef long long __u64;
typedef __u64 ipl_t;
typedef __u64 __address;

#define __sparc64_TYPES_H__
#define __ALIGN_H__

#include "../../arch/sparc64/include/stack.h"
#include "../../arch/sparc64/include/context.h"

#define FILENAME "../../arch/sparc64/include/context_offset.h"

int main(void)
{
	FILE *f;
	struct context *pctx = NULL;
	

	f = fopen(FILENAME,"w");
	if (!f) {
		perror(FILENAME);
		return 1;
	}

	fprintf(f, "/* This file is automatically generated by %s. */\n", __FILE__);	

	fprintf(f,"/* struct context */\n");
	fprintf(f,"#define OFFSET_SP  0x%x\n",((int)&pctx->sp) - (int )pctx);
	fprintf(f,"#define OFFSET_PC  0x%x\n",((int)&pctx->pc) - (int )pctx);
	fprintf(f,"#define OFFSET_I0  0x%x\n",((int)&pctx->i0) - (int )pctx);
	fprintf(f,"#define OFFSET_I1  0x%x\n",((int)&pctx->i1) - (int )pctx);
	fprintf(f,"#define OFFSET_I2  0x%x\n",((int)&pctx->i2) - (int )pctx);
	fprintf(f,"#define OFFSET_I3  0x%x\n",((int)&pctx->i3) - (int )pctx);
	fprintf(f,"#define OFFSET_I4  0x%x\n",((int)&pctx->i4) - (int )pctx);
	fprintf(f,"#define OFFSET_I5  0x%x\n",((int)&pctx->i5) - (int )pctx);
	fprintf(f,"#define OFFSET_FP  0x%x\n",((int)&pctx->fp) - (int )pctx);
	fprintf(f,"#define OFFSET_I7  0x%x\n",((int)&pctx->i7) - (int )pctx);
	fprintf(f,"#define OFFSET_L0  0x%x\n",((int)&pctx->l0) - (int )pctx);
	fprintf(f,"#define OFFSET_L1  0x%x\n",((int)&pctx->l1) - (int )pctx);
	fprintf(f,"#define OFFSET_L2  0x%x\n",((int)&pctx->l2) - (int )pctx);
	fprintf(f,"#define OFFSET_L3  0x%x\n",((int)&pctx->l3) - (int )pctx);
	fprintf(f,"#define OFFSET_L4  0x%x\n",((int)&pctx->l4) - (int )pctx);
	fprintf(f,"#define OFFSET_L5  0x%x\n",((int)&pctx->l5) - (int )pctx);
	fprintf(f,"#define OFFSET_L6  0x%x\n",((int)&pctx->l6) - (int )pctx);
	fprintf(f,"#define OFFSET_L7  0x%x\n",((int)&pctx->l7) - (int )pctx);
	fprintf(f,"#define OFFSET_CLEANWIN  0x%x\n",((int)&pctx->cleanwin) - (int )pctx);

	fclose(f);

	return 0;
}
