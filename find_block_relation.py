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


all_real_blocks =[269576, 269728, 269844, 269936, 270092, 270180, 270252, 270348, 270424, 270516, 270588, 270636, 270652, 270676, 270768, 270788, 270808, 270832, 270856, 270876, 270908, 272968, 273000, 273024, 273040, 270936, 271096, 271208, 271324, 271444, 271536, 271640, 271728, 271800, 271916, 271980, 272072, 272152, 272276, 272344, 272392, 272480, 272496, 272552, 272576, 272612, 272664, 272688, 272728, 272796, 272828, 272856, 272872, 272900, 272924, 272940, 273072]
all_child_prologue_addr =  [[270936, 271096, 271208, 271324, 271444, 271536, 271640, 271728, 271800, 271916, 271980, 272072, 272152, 272276, 272344, 272392, 272480, 272496, 272552, 272576, 272612, 272664, 272688, 272728, 272796, 272828, 272856, 272872, 272900, 272924, 272940]]
all_child_prologue_last_ins_ea = [270980]

angr_main(all_real_blocks,all_child_prologue_addr,all_child_prologue_last_ins_ea,0x41D08,"libgeiri.so")
