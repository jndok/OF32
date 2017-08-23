//
//  of32.c
//  OF32
//
//  Created by jndok on 23/08/2017.
//  Copyright © 2017 jndok. All rights reserved.
//

#include <stdio.h>
#include <assert.h>

#include "machoman.h"

void *base = NULL;
uint32_t kbase = 0;

struct mach_header *mh = NULL;
struct symtab_command *symtab = NULL;

/* patchfinder32 - credits to planetbeing (https://github.com/planetbeing/ios-jailbreak-patchfinder) */

static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if(bit_range(imm12, 11, 10) == 0)
    {
        switch(bit_range(imm12, 9, 8))
        {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else
    {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t* i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}


static int insn_is_add_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_mov_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_is_movt(uint16_t* i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t* i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_ldr_imm(uint16_t* i)
{
    uint8_t opA = bit_range(*i, 15, 12);
    uint8_t opB = bit_range(*i, 11, 9);
    
    return opA == 6 && (opB & 4) == 4;
}

static int insn_ldr_imm_rt(uint16_t* i)
{
    return (*i & 7);
}

static int insn_ldr_imm_imm(uint16_t* i)
{
    return (((*i >> 6) & 0x1F) << 2);
}

int insn_ldr_reg_rt(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return *i & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

int insn_ldr_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return (*i >> 6) & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_bl(uint16_t* i)
{
    if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

static uint32_t insn_bl_imm32(uint16_t* i)
{
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

/* patchfinder32 - END */

struct nlist *find_sym(const char *sym)
{
    if (!sym || !base || !symtab)
        return NULL;
    
    void *psymtab = base + symtab->symoff;
    void *pstrtab = base + symtab->stroff;
    
    struct nlist *entry = (struct nlist *)psymtab;
    for (uint32_t i = 0; i < symtab->nsyms; i++, entry++)
        if (!strcmp(sym, (char *)(pstrtab + entry->n_un.n_strx)))
            return entry;
    
    return NULL;
}

uint32_t find_sig(uint8_t *sig)
{
    if (!mh || !sig)
        return -1;
    
    struct segment_command *text = find_segment_command(mh, SEG_TEXT);
    if (!text)
        return -2;
    
    void *search_base = (base + text->fileoff);
    void *p = memmem(search_base, text->filesize, sig, sizeof(sig));
    if (!p)
        return -3;
    
    return (uint32_t)(p - base);
}

/* offset finders */

#define OSSERIALIZER_SERIALIZE_SYMBOL_NAME  "__ZNK12OSSerializer9serializeEP11OSSerialize"
#define OSSYMBOL_GETMETACLASS_SYMBOL_NAME   "__ZNK8OSSymbol12getMetaClassEv"
#define BUFATTR_CPX_SYMBOL_NAME             "_bufattr_cpx"
#define COPYIN_SYMBOL_NAME                  "_copyin"
#define KERNEL_PMAP_SYMBOL_NAME             "_kernel_pmap"

uint32_t find_OSSerializer_serialize(void)
{
    struct nlist *n = find_sym(OSSERIALIZER_SERIALIZE_SYMBOL_NAME);
    assert(n);
    
    return n->n_value;
}

uint32_t find_OSSymbol_getMetaClass(void)
{
    struct nlist *n = find_sym(OSSYMBOL_GETMETACLASS_SYMBOL_NAME);
    assert(n);
    
    return n->n_value;
}

uint32_t find_calend_gettime(void)
{
    struct nlist *n = find_sym("_clock_get_calendar_nanotime");
    assert(n);
    
    uint32_t xref = n->n_value;
    
    for (uint16_t *p = (uint16_t *)(base + find_segment_command(mh, SEG_TEXT)->fileoff); p < (uint16_t *)(base + find_segment_command(mh, SEG_TEXT)->filesize); p++)
        if (insn_is_32bit(p) && insn_is_bl(p)) {
            uint32_t ip = (uint32_t)((void *)p - base) + kbase;
            if ((ip + (int32_t)insn_bl_imm32(p) + 4) == xref)
                return ip; // XXX: assuming first xref is correct one, may not be (?)
        }
    
    return 0;
}

uint32_t find_bufattr_cpx(void)
{
    struct nlist *n = find_sym(BUFATTR_CPX_SYMBOL_NAME);
    assert(n);
    
    return n->n_value;
}

uint32_t find_clock_ops(void)
{
    struct nlist *n = find_sym("_clock_get_system_value");
    assert(n);
    
    uint32_t val = 0;
    
    for (uint16_t *p = (uint16_t *)(base + (n->n_value - kbase)); *p != 0xBF00; p++) {
        if (insn_is_mov_imm(p) && (!insn_mov_imm_rd(p))) {
            val = insn_mov_imm_imm(p);
        } else if (insn_is_movt(p) && (!insn_movt_rd(p))) {
            val |= (insn_movt_imm(p) << 16);
        } else if (insn_is_add_reg(p) && (!insn_add_reg_rd(p)) && (insn_add_reg_rm(p) == 0xF)) {
            uint32_t ip = (uint32_t)((void *)(p+2) - base) + kbase;
            uint32_t *addr = (uint32_t *)(base + ((ip + val) - kbase));
            assert(*addr);
            
            return (*addr) + 0xC;
        }
    }
    
    return 0;
}

uint32_t find_copyin(void)
{
    struct nlist *n = find_sym(COPYIN_SYMBOL_NAME);
    assert(n);
    
    return n->n_value;
}

uint32_t find_bx_lr(void)
{
    return find_bufattr_cpx() + 0x2;
}

uint32_t find_write_gadget(void)
{
    struct nlist *n = find_sym("_enable_kernel_vfp_context");
    assert(n);
    
    uint16_t *p = NULL;
    for (p = (uint16_t *)(base + (n->n_value - kbase)); *p != 0x100C; p--);
    
    return (uint32_t)((void *)p - base) + kbase;
}

uint32_t find_vm_kernel_addrperm(void)
{
    struct nlist *n = find_sym("_vm_kernel_addrperm_external");
    assert(n);
    
    uint32_t val = 0;
    
    for (uint16_t *p = (uint16_t *)(base + (n->n_value - kbase)); *p != 0xBF00; p++) {
        if (insn_is_mov_imm(p) && (insn_mov_imm_rd(p) == 2)) {
            val = insn_mov_imm_imm(p);
        } else if (insn_is_movt(p) && (insn_movt_rd(p) == 2)) {
            val |= (insn_movt_imm(p) << 16);
        } else if (insn_is_add_reg(p) && (insn_add_reg_rd(p) == 2) && (insn_add_reg_rm(p) == 0xF)) {
            uint32_t ip = (uint32_t)((void *)(p+2) - base) + kbase;
            val += ip;
        } else if (insn_is_ldr_imm(p) && (insn_ldr_imm_rt(p) == 2)) {
            val += insn_ldr_imm_imm(p);
            val -= 0x8;
            
            return val;
        }
    }
    
    return 0;
}

uint32_t find_kernel_pmap(void)
{
    struct nlist *n = find_sym(KERNEL_PMAP_SYMBOL_NAME);
    assert(n);
    
    return n->n_value;
}

uint32_t find_flush_dcache(void)
{
    uint8_t sig[] = {
        0x00, 0x00, 0xA0, 0xE3,
        0x5E, 0x0F, 0x07, 0xEE
    };
    
    uint32_t off = find_sig((void *)&sig);
    return (uint32_t)(off + kbase);
}

uint32_t find_invalidate_tlb(void)
{
    uint8_t sig[] = {
        0x00, 0x00, 0xA0, 0xE3,
        0x17, 0x0F, 0x08, 0xEE,
        0x4B, 0xF0, 0x7F, 0xF5,
        0x6F, 0xF0, 0x7F, 0xF5,
        0x1E, 0xFF, 0x2F, 0xE1
    };
    
    uint32_t off = find_sig((void *)&sig);
    return (uint32_t)(off + kbase);
}

uint32_t find_allproc(void)
{
    struct nlist *n = find_sym("_groupmember");
    struct nlist *n2 = find_sym("_kauth_cred_get");
    struct nlist *n3 = find_sym("_lck_mtx_lock");
    
    assert(n);
    assert(n2);
    assert(n3);
    
    boolean_t mark1 = FALSE;
    boolean_t mark2 = FALSE;
    
    uint32_t *p = NULL;
    for (p = (uint32_t *)(base + (n->n_value - kbase));; p++) {
        if (insn_is_32bit((uint16_t *)p) && insn_is_bl((uint16_t *)p)) {
            uint32_t ip = (uint32_t)((void *)p - base) + kbase;
            uint32_t val = (ip + (int32_t)insn_bl_imm32((uint16_t *)p) + 4);
            
            if (!mark1 && (val == n2->n_value))
                mark1++;
            else if (!mark2 && mark1 && (val == n3->n_value))
                break;
        }
    }
    
    uint32_t val = 0;
        
    for (uint16_t *p2 = (uint16_t *)p; *p2 != 0xBF00; p2++) {
        if (insn_is_mov_imm(p2) && (!insn_mov_imm_rd(p2))) {
            val = insn_mov_imm_imm(p2);
        } else if (insn_is_movt(p2) && (!insn_movt_rd(p2))) {
            val |= (insn_movt_imm(p2) << 16);
        } else if (insn_is_add_reg(p2) && (!insn_add_reg_rd(p2)) && (insn_add_reg_rm(p2) == 0xF)) {
            uint32_t ip = (uint32_t)((void *)(p2+2) - base) + kbase;
            val += ip;
        } else if (insn_is_ldr_imm(p2) && (!insn_ldr_imm_rt(p2))) {
            val += insn_ldr_imm_imm(p2);
            val += 0x8;
            
            return val;
        }
    }
    
    return 0;
}

uint32_t find_proc_ucred(void)
{
    struct nlist *n = find_sym("_proc_ucred");
    assert(n);
    
    uint32_t *addr = (uint32_t *)(base + (n->n_value - kbase));
    
    return ((*addr) >> 16);
}

uint32_t find_setreuid(void)
{
    uint8_t sig[] = {
        0xf0, 0xb5, 0x03, 0xaf,
        0x2d, 0xe9, 0x00, 0x0d,
        0x87, 0xb0, 0x04, 0x46,
        0x02, 0x91, 0x03, 0x94,
        0xd1, 0xf8, 0x00, 0xb0,
        0x4d, 0x68, 0xdf, 0xf7
    };
    
    uint32_t off = find_sig((void *)&sig);
    return (uint32_t)(off + kbase);
}

uint32_t find_task_for_pid(void)
{
    uint8_t sig[] = {
        0xf0, 0xb5, 0x03, 0xaf,
        0x2d, 0xe9, 0x00, 0x0d,
        0x84, 0xb0, 0x01, 0x46,
        0x91, 0xe8, 0x41, 0x08,
        0x00, 0x21, 0x03, 0x91
    };
    
    uint32_t off = find_sig((void *)&sig);
    return (uint32_t)(off + kbase);
}

int main(int argc, const char * argv[]) {
    
    if (argc != 2) {
        printf("Usage: ./OF32 [kernelcache_path]\n");
        return 1;
    }
    
    macho_map_t *map = map_macho_with_path(argv[1], O_RDONLY);
    assert(map);
    
    mh = (struct mach_header *)(map->map_data);
    
    if (mh->magic != MH_MAGIC) {
        printf("Error: Invalid kernelcache!\n");
        return 2;
    }
    
    base = map->map_data;
    kbase = find_segment_command(mh, SEG_TEXT)->vmaddr;
    
    symtab = find_symtab_command(mh);
    assert(symtab);
    
    uint32_t OSSerializer_serialize_off = find_OSSerializer_serialize();
    uint32_t OSSymbol_getMetaClass_off = find_OSSymbol_getMetaClass();
    uint32_t calend_gettime_off = find_calend_gettime();
    uint32_t bufattr_cpx_off = find_bufattr_cpx();
    uint32_t clock_ops_off = find_clock_ops();
    uint32_t copyin_off = find_copyin();
    uint32_t bx_lr_off = find_bx_lr();
    uint32_t write_gadget_off = find_write_gadget();
    uint32_t vm_kernel_addrperm = find_vm_kernel_addrperm();
    uint32_t kernel_pmap_off = find_kernel_pmap();
    uint32_t flush_dcache_off = find_flush_dcache();
    uint32_t invalidate_tlb_off = find_invalidate_tlb();
    uint32_t setreuid_off = find_setreuid();
    uint32_t proc_ucred_off = find_proc_ucred();
    uint32_t task_for_pid_off = find_task_for_pid();
    uint32_t allproc_off = find_allproc();
    
    /* print offsets */
    
    printf("find_OSSerializer_serialize(): %#x (slid: %#x)\n",     OSSerializer_serialize_off - kbase, OSSerializer_serialize_off);
    printf("find_OSSymbol_getMetaClass(): %#x (slid: %#x)\n",      OSSymbol_getMetaClass_off - kbase, OSSymbol_getMetaClass_off);
    printf("find_calend_gettime(): %#x (slid: %#x)\n",             calend_gettime_off - kbase, calend_gettime_off);
    printf("find_bufattr_cpx(): %#x (slid: %#x)\n",                bufattr_cpx_off - kbase, bufattr_cpx_off);
    printf("find_clock_ops(): %#x (slid: %#x)\n",                  clock_ops_off - kbase, clock_ops_off);
    printf("find_copyin(): %#x (slid: %#x)\n",                     copyin_off - kbase, copyin_off);
    printf("find_bx_lr(): %#x (slid: %#x)\n",                      bx_lr_off - kbase, bx_lr_off);
    printf("find_write_gadget(): %#x (slid: %#x)\n",               write_gadget_off - kbase, write_gadget_off);
    printf("find_vm_kernel_addrperm(): %#x (slid: %#x)\n",         vm_kernel_addrperm - kbase, vm_kernel_addrperm);
    printf("find_kernel_pmap(): %#x (slid: %#x)\n",                kernel_pmap_off - kbase, kernel_pmap_off);
    printf("find_flush_dcache(): %#x (slid: %#x)\n",               flush_dcache_off - kbase, flush_dcache_off);
    printf("find_invalidate_tlb(): %#x (slid: %#x)\n",             invalidate_tlb_off - kbase, invalidate_tlb_off);
    printf("find_proc_ucred(): %#x\n",                             proc_ucred_off);
    printf("find_setreuid(): %#x (slid: %#x)\n",                   setreuid_off - kbase, setreuid_off);
    printf("find_task_for_pid(): %#x (slid: %#x)\n",               task_for_pid_off - kbase, task_for_pid_off);
    printf("find_allproc(): %#x (slid: %#x)\n",                    allproc_off - kbase, allproc_off);
    
    
    return 0;
}
