from collections import deque

import ida_funcs
import idaapi
import idc

def get_block_by_address(ea):
    # 获取地址所在的函数
    func = idaapi.get_func(ea)
    blocks = idaapi.FlowChart(func)
    for block in blocks:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None

def find_loop_heads(func):
    loop_heads = set()
    queue = deque()
    block = get_block_by_address(func)
    queue.append((block, []))
    while len(queue) > 0:
        cur_block, path = queue.popleft()
        if cur_block.start_ea in path:
            loop_heads.add(cur_block.start_ea)
            continue
        path = path+ [cur_block.start_ea]
        queue.extend((succ, path) for succ in cur_block.succs())
    all_loop_heads = list(loop_heads)
    all_loop_heads.sort()#升序排序,保证函数开始的主循环头在第一个
    return all_loop_heads

def find_converge_addr(loop_head_addr):
    converge_addr = None
    block = get_block_by_address(loop_head_addr)
    preds = block.preds()
    pred_list = list(preds)
    if len(pred_list) == 2:#循环头的前驱有两个基本块,这种一般是标准ollvm
        for pred in pred_list:
            tmp_list = list(pred.preds())
            if len(tmp_list) >1:#
                converge_addr = pred.start_ea
    else:#非标准ollvm
        converge_addr= loop_head_addr
    return converge_addr

def get_basic_block_size(bb):
    return bb.end_ea - bb.start_ea

def add_block_color(ea):
    block = get_block_by_address(ea)
    curr_addr = block.start_ea
    while curr_addr <block.end_ea:
        idc.set_color(curr_addr,idc.CIC_ITEM,0xffcc33)
        curr_addr = idc.next_head(curr_addr)

#清除函数中的颜色渲染
def del_func_color(curr_addr):
    end_ea = idc.find_func_end(curr_addr)
    while curr_addr < end_ea:
        idc.set_color(curr_addr, idc.CIC_ITEM, 0xffffffff)
        curr_addr = idc.next_head(curr_addr)

def find_ret_block_addr(blocks):
    for block in blocks:
        succs = block.succs()  # 获取后继块
        succs_list = list(succs)  # 转为list结构

        end_ea = block.end_ea
        last_ins_ea = idc.prev_head(end_ea)
        mnem = idc.print_insn_mnem(last_ins_ea)

        if len(succs_list) == 0:
            if mnem == "RET":
                # 如果直接去把RET指令所在的块作为返回块的表示 最后可能会出现反混淆代码赋值错误
                # 所以这里取RET指令的前驱块并且前驱块的大小不能只有一条指令,一般这个块都是有分支的
                ori_ret_block = block
                while True:
                    tmp_block = block.preds()
                    pred_list = list(tmp_block)
                    if len(pred_list) == 1:
                        block = pred_list[0]
                        if get_basic_block_size(block) == 4:
                            continue
                        else:
                            break
                    else:
                        break

                # 此处while循环是为了解决当上述的ret块作为子分发器时,需要重新更改ret块为带ret指令的块
                block2 = block
                num = 0
                i = 0
                while True:
                    i += 1
                    succs_block = block2.succs()
                    for succ in succs_block:
                        child_succs = succ.succs()
                        succ_list = list(child_succs)
                        if len(succ_list) != 0:
                            block2 = succ
                            num += 1
                    if num > 2:
                        block = ori_ret_block
                        break
                    if i > 2:
                        break
                return block.start_ea

def find_all_real_block(func_ea):

    blocks = idaapi.FlowChart(idaapi.get_func(func_ea))

    loop_heads = find_loop_heads(func_ea)#获取所有循环头 非标准ollvm出现在多个主分发器
    print(f"循环头数量:{len(loop_heads)}----{[hex(loop_head) for loop_head in loop_heads]}")

    all_real_block=[]
    for loop_head_addr in loop_heads:
        loop_head_block = get_block_by_address(loop_head_addr)#获取循环头
        loop_head_preds = list(loop_head_block.preds())#获取循环头的所有前驱块
        loop_head_preds_addr = [loop_head_pred.start_ea for loop_head_pred in loop_head_preds]#把所有前驱块转为数组

        converge_addr = find_converge_addr(loop_head_addr)#获取汇聚块地址

        real_blocks = []

        if loop_head_addr != converge_addr:
            loop_head_preds_addr.remove(converge_addr)#移除汇聚块,剩下的一个是序言块
            real_blocks.extend(loop_head_preds_addr)

        converge_block = get_block_by_address(converge_addr)
        list_preds = list(converge_block.preds())
        for pred_block in list_preds:
            end_ea = pred_block.end_ea
            last_ins_ea = idc.prev_head(end_ea)
            mnem = idc.print_insn_mnem(last_ins_ea)  # 获取基本块最后一条指令的操作符

            size = get_basic_block_size(pred_block)
            if size > 4 and "B." not in mnem:
                start_ea = pred_block.start_ea
                mnem = idc.print_insn_mnem(start_ea)
                if mnem == "CSEL":
                    csel_preds = pred_block.preds()
                    for csel_pred in csel_preds:

                        real_blocks.append(csel_pred.start_ea)
                else:
                    real_blocks.append(pred_block.start_ea)

        real_blocks.sort()#排序后第一个元素始终序言块
        all_real_block.append(real_blocks)
        print("子循环头:", [hex(child_block_ea) for child_block_ea in real_blocks])

    #获取return块
    ret_addr = find_ret_block_addr(blocks)
    all_real_block.append(ret_addr)
    print("all_real_block:",all_real_block)

    all_real_block_list = []
    for real_blocks in all_real_block:
        if isinstance(real_blocks, list):  # 如果是列表，用 extend
            all_real_block_list.extend(real_blocks)
        else:  # 如果不是列表，用 append
            all_real_block_list.append(real_blocks)

    for real_block_ea in all_real_block_list:
        # idc.add_bpt(real_block_ea)#断点
        add_block_color(real_block_ea)#渲染颜色

    print("\n所有真实块获取完成")
    print("===========INT===============")
    print(all_real_block_list)
    print("===========HEX===============")
    print(f"数量:{len(all_real_block_list)}")
    print([hex(real_block_ea) for real_block_ea in all_real_block_list],"\n")

    #移除ret地址和主序言块相关真实块,保留子序言块相关的真实块
    all_child_prologue_addr = all_real_block.copy()
    all_child_prologue_addr.remove(ret_addr)
    all_child_prologue_addr.remove(all_child_prologue_addr[0])
    print("所有子序言块相关的真实块地址:",all_child_prologue_addr)

    all_child_prologue_last_ins_ea = []
    for child_prologue_array in all_child_prologue_addr:
        child_prologue_addr = child_prologue_array[0]
        child_prologue_block = get_block_by_address(child_prologue_addr)
        child_prologue_end_ea = child_prologue_block.end_ea
        child_prologue_last_ins_ea = idc.prev_head(child_prologue_end_ea)
        all_child_prologue_last_ins_ea.append(child_prologue_last_ins_ea)
    # print("所有子序言块的最后一条指令的地址:", [hex(ea) for ea in all_child_prologue_last_ins_ea])
    print("所有子序言块的最后一条指令的地址:", all_child_prologue_last_ins_ea)

    return all_real_block_list,all_child_prologue_addr,all_child_prologue_last_ins_ea

'''
========================angr执行=============================
'''
import logging
import time

import angr
from tqdm import tqdm

logging.getLogger('angr').setLevel(logging.ERROR)#过滤angr日志,只显示ERROR日志,里面许多的WARNING输出影响日志分析

def capstone_decode_csel(insn):
    operands = insn.op_str.replace(' ', '').split(',')
    dst_reg = operands[0]
    condition = operands[3]
    reg1 = operands[1]
    reg2 = operands[2]
    return dst_reg,reg1, reg2,condition

def print_reg(state,reg_name):
    value = state.regs.get(reg_name)
    print(f"地址:{hex(state.addr)},寄存器:{reg_name},value:{value}")

def find_state_succ(proj,base,local_state,flag,real_blocks,real_block_addr,path):
    ins = local_state.block().capstone.insns[0]
    dst_reg, reg1, reg2,condition = capstone_decode_csel(ins)
    val1 = local_state.regs.get(reg1)
    val2 = local_state.regs.get(reg2)
    # print(f"寄存器值 {reg1}:{val1},{reg2}:{val2}")

    sm = proj.factory.simgr(local_state)
    sm.step(num_inst=1)
    tmp_state = sm.active[0]
    if flag:
        setattr(tmp_state.regs, dst_reg, val1)  # 给寄存器的条件判断结果设为真
    else:
        setattr(tmp_state.regs, dst_reg, val2)  # 给寄存器的条件判断结果设为假

    # print(f"开始运行的寄存器:{sm.active[0].regs.get(dst_reg)}")
    while len(sm.active):
        # print(sm.active)
        for active_state in sm.active:
            ins_offset = active_state.addr - base
            # if ins_offset == 0x41DC0:
            #     print_reg("x8")
            if ins_offset in real_blocks:
                value = path[real_block_addr]
                if ins_offset not in value:#如果当前后继块不在path里,则添加,否则继续循环寻找
                    value.append(ins_offset)
                    return ins_offset
        sm.step(num_inst=1)

def find_block_succ(proj,base,func_offset,state, real_block_addr, real_blocks, path):
    msm = proj.factory.simgr(state)  #构造模拟器

    # 第一个while的作用:寻找到传入的真实块地址作为主块,再复制一份当前state,准备后继块获取的操作
    while len(msm.active):
        # print(f"路径{msm.active}")
        for active_state in msm.active:
            offset = active_state.addr - base
            if offset == real_block_addr:  # 找到真实块
                mstate = active_state.copy()  #复制state,为后继块的获取做准备
                msm2 = proj.factory.simgr(mstate)
                msm2.step(num_inst=1)  # 防止下个while里获取后继块的时候key和value重复
                #第二个while的作用:寻找真实块的所有后继块
                while len(msm2.active):
                    # print(msm2.active)
                    for mactive_state in msm2.active:
                        ins_offset = mactive_state.addr - base
                        if ins_offset in real_blocks:#无分支块
                            #在无条件跳转中,并且有至少两条路径同时执行到真实块时,取非ret块的真实块
                            msm2_len = len(msm2.active)
                            if msm2_len > 1:
                                tmp_addrs = []
                                for s in msm2.active:
                                    moffset = s.addr-base
                                    tmp_value = path[real_block_addr]
                                    if moffset in real_blocks and moffset not in tmp_value:
                                        tmp_addrs.append(moffset)
                                if len(tmp_addrs) > 1:
                                    print("当前至少有两个路径同时执行到真实块:",[hex(tmp_addr) for tmp_addr in tmp_addrs])
                                    ret_addr = real_blocks[len(real_blocks)-1]
                                    if ret_addr in tmp_addrs:
                                        tmp_addrs.remove(ret_addr)
                                    ins_offset = tmp_addrs[0]
                                    print("两个路径同时执行到真实块最后取得:",hex(ins_offset))

                            value = path[real_block_addr]
                            if ins_offset not in value:
                                value.append(ins_offset)
                            print(f"无条件跳转块关系:{hex(real_block_addr)}-->{hex(ins_offset)}")
                            return

                        ins = mactive_state.block().capstone.insns[0]
                        if ins.mnemonic == 'csel':#有分支块
                            state_true = mactive_state.copy()
                            state_true_succ_addr = find_state_succ(proj,base,state_true, True, real_blocks,real_block_addr, path)

                            state_false = mactive_state.copy()
                            state_false_succ_addr = find_state_succ(proj,base,state_false, False, real_blocks,real_block_addr, path)


                            if state_true_succ_addr is None or state_false_succ_addr is None:
                                print("csel错误指令地址:",hex(ins_offset))
                                # print(f"csel后继有误:{hex(real_block_addr)}-->{state_true_succ_addr},{state_false_succ_addr}")
                                print(f"csel后继有误:{hex(real_block_addr)}-->{hex(state_true_succ_addr) if state_true_succ_addr is not None else state_true_succ_addr},"
                                      f"{hex(state_false_succ_addr) if state_false_succ_addr is not None else state_false_succ_addr}")
                                return "erro"

                            print(f"csel分支跳转块关系:{hex(real_block_addr)}-->{hex(state_true_succ_addr)},{hex(state_false_succ_addr)}")
                            return
                    msm2.step(num_inst=1)
                return  # 真实块集合中的最后一个基本块如果最后没找到后继,说明是return块,直接返回
        msm.step(num_inst=1)

def angr_main(real_blocks,all_child_prologue_addr,all_child_prologue_last_ins_ea,func_offset,file_path):
    proj = angr.Project(file_path, auto_load_libs=False)
    base = proj.loader.min_addr
    func_addr = base + func_offset
    init_state = proj.factory.blank_state(addr=func_addr)
    init_state.options.add(angr.options.CALLLESS)

    path = {key: [] for key in real_blocks}  # 初始化所有键的值为空列表
    ret_addr = real_blocks[len(real_blocks) - 1]

    first_block = proj.factory.block(func_addr)
    first_block_insns = first_block.capstone.insns
    # 获取主序言块的最后一条指令
    first_block_last_ins = first_block_insns[len(first_block_insns) - 1]

    for real_block_addr in tqdm(real_blocks):
        if ret_addr == real_block_addr:
            continue

        prologue_block_addr = 0
        child_prologue_last_ins_ea = 0
        if len(all_child_prologue_addr)>0:
            for index,child_prologue_array in enumerate(all_child_prologue_addr):
                if real_block_addr in child_prologue_array:
                    prologue_block_addr = child_prologue_array[0]+base
                    child_prologue_last_ins_ea = all_child_prologue_last_ins_ea[index]

        state = init_state.copy()#拷贝初始化state,独立state
        print("正在寻找:",hex(real_block_addr))

        def jump_to_address(state):
            state.regs.pc = base + real_block_addr - 4

        def jump_to_child_prologue_address(state):
            state.regs.pc = prologue_block_addr - 4

        if prologue_block_addr == 0:
            #当序言块执行完后(初始化后续条件判断的寄存器),将最后一条指令的pc寄存器指向真实块地址
            if real_block_addr != func_offset:
                proj.hook(first_block_last_ins.address, jump_to_address, first_block_last_ins.size)
        else:
            proj.hook(first_block_last_ins.address, jump_to_child_prologue_address, first_block_last_ins.size)
            proj.hook(child_prologue_last_ins_ea, jump_to_address, 4)

        ret = find_block_succ(proj,base,func_offset,state, real_block_addr, real_blocks, path)
        if ret == "erro":
            return

    hex_dict = {
        hex(key): [hex(value) for value in values]
        for key, values in path.items()
    }

    print("真实块控制流:\n",hex_dict)
    # 返回重建的控制流
    return hex_dict

'''
重建控制流
'''
from collections import deque
import idaapi
import idautils
import idc
import keystone

#初始化Ks arm64架构的so,模式:小端序
ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
def patch_ins_to_nop(ins):
    size = idc.get_item_size(ins)
    for i in range(size):
        idc.patch_byte(ins + i,0x90)

def get_block_by_address(ea):
    func = idaapi.get_func(ea)
    blocks = idaapi.FlowChart(func)
    for block in blocks:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None



def patch_branch(patch_list):

    for ea in patch_list:
        values = patch_list[ea]
        if len(values) == 0:#如果后继块为0,基本都是return块,不需要patch,直接跳过
            continue
        block = get_block_by_address(int(ea, 16))
        start_ea = block.start_ea
        end_ea = block.end_ea
        last_ins_ea = idc.prev_head(end_ea)#因为block.end_ea获取的地址是块最后一个地址的下一个地址,所以需要向上取一个地址
        if len(values) == 2:#分支块的patch
            flag = False
            for ins in idautils.Heads(start_ea,end_ea):#获取指定范围内的所有指令
                  if idc.print_insn_mnem(ins) == "CSEL":
                      condition = idc.print_operand(ins,3)
                      encoding, count = ks.asm(f'B.{condition} {values[0]}',ins)#生成CSEL指令处patch的汇编
                      encoding2, count2 = ks.asm(f'B {values[1]}', last_ins_ea)#生成块最后一个地址指令处patch的汇编
                      for i in range(4):
                          idc.patch_byte(ins+ i, encoding[i])
                      for i in range(4):
                          idc.patch_byte(last_ins_ea + i, encoding2[i])
                      flag = True
            if not flag:#如果在有分支跳转的情况下没有找到CSEL指令,就要在当前基本块的最后两条指令做处理。此基本块的下一条指令就是csel
                ins = idc.prev_head(last_ins_ea)
                succs = block.succs()
                succs_list = list(succs)
                csel_ea = succs_list[0].start_ea
                condition = idc.print_operand(csel_ea, 3)#获取csel指令的条件判断
                encoding, count = ks.asm(f'B.{condition} {values[0]}', ins)  # 生成CSEL指令处patch的汇编
                encoding2, count2 = ks.asm(f'B {values[1]}', last_ins_ea)  # 生成块最后一个地址指令处patch的汇编
                try:
                    for i in range(4):
                        idc.patch_byte(ins + i, encoding[i])
                    for i in range(4):
                        idc.patch_byte(last_ins_ea + i, encoding2[i])
                except:
                    print("except")


        else:#无分支块的patch
            encoding, count = ks.asm(f'B {values[0]}', last_ins_ea)
            for i in range(4):
                idc.patch_byte(last_ins_ea + i, encoding[i])
    print("pach over!!!")

def find_all_useless_block(func_ea,real_blocks):
    blocks = idaapi.FlowChart(idaapi.get_func(func_ea))
    local_real_blocks = real_blocks.copy()
    useless_blocks = []
    ret_block_addr = local_real_blocks[len(local_real_blocks)-1]
    queue = deque()
    ret_block = get_block_by_address(ret_block_addr)
    queue.append(ret_block)
    while len(queue) > 0:#处理ret块相关的后继块
        cur_block= queue.popleft()
        queue.extend(succ for succ in cur_block.succs())
        ret_flag = False
        for succ in cur_block.succs():
            local_real_blocks.append(succ.start_ea)
            end_ea = succ.end_ea
            last_ins_ea = idc.prev_head(end_ea)
            mnem = idc.print_insn_mnem(last_ins_ea)
            if mnem == "RET":
                ret_flag = True
        if ret_flag:
            break
        # local_real_blocks.extend(succ.start_ea for succ in cur_block.succs())
    for block in blocks:
        start_ea = block.start_ea
        if start_ea not in local_real_blocks:
            useless_blocks.append(start_ea)
    print("所有的无用块:",[hex(b)for b in useless_blocks])
    return useless_blocks

def patch_useless_blocks(func_ea,real_blocks):
    useless_blocks = find_all_useless_block(func_ea, real_blocks)
    # print(useless_blocks)
    for useless_block_addr in useless_blocks:
        block = get_block_by_address(useless_block_addr)
        start_ea = block.start_ea
        end_ea = block.end_ea

        insns = idautils.Heads(start_ea, end_ea)
        for ins in insns:
            patch_ins_to_nop(ins)
    print("无用块nop完成")

def main(func_ea):
    file_path = idc.get_input_file_path()#获取当前so路径
    all_real_block_list,all_child_prologue_addr,all_child_prologue_last_ins_ea = find_all_real_block(func_ea)#获取所有真实块
    patch_list = angr_main(all_real_block_list,all_child_prologue_addr,all_child_prologue_last_ins_ea,func_ea,file_path)#angr执行获取真实块之间的控制流
    patch_branch(patch_list)#重建控制流

    # patch_useless_blocks(func_ea,all_real_blocks)#nop无用块
    # ida_funcs.reanalyze_function(ida_funcs.get_func(func_ea))#刷新函数控制流图
    # print("控制流图已刷新")

main(0x41D08)