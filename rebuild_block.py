from collections import deque

import ida_funcs
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
                except :
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

patch_list ={'0x41d08': ['0x4221c'], '0x41da0': ['0x421c4', '0x42258'], '0x41e14': ['0x41fac'], '0x41e70': ['0x4213c'], '0x41f0c': ['0x42a80', '0x4200c'], '0x41f64': ['0x42ab0'], '0x41fac': ['0x42a80', '0x421d8'], '0x4200c': ['0x42a90'], '0x42058': ['0x41f64', '0x42ab0'], '0x420b4': ['0x41e70', '0x42208'], '0x420fc': ['0x42ab0', '0x421f0'], '0x4212c': ['0x42a68'], '0x4213c': ['0x4212c', '0x42ab0'], '0x42154': ['0x420b4'], '0x421b0': ['0x41fac'], '0x421c4': ['0x41f0c'], '0x421d8': ['0x42258', '0x42ab0'], '0x421f0': ['0x42ab0', '0x4223c'], '0x42208': ['0x4213c'], '0x4221c': ['0x42154', '0x4212c'], '0x4223c': ['0x41da0'], '0x42a48': ['0x42058'], '0x42a68': ['0x420fc', '0x42ab0'], '0x42a80': ['0x421d8'], '0x42a90': ['0x421b0', '0x41e14'], '0x42258': ['0x42a1c'], '0x422f8': ['0x42a48'], '0x42368': ['0x4266c'], '0x423dc': ['0x42368'], '0x42454': ['0x429d8', '0x426c8'], '0x424b0': ['0x42570', '0x42860'], '0x42518': ['0x42454'], '0x42570': ['0x42a04'], '0x425b8': ['0x428e4'], '0x4262c': ['0x429d8'], '0x4266c': ['0x42930', '0x428a8'], '0x426c8': ['0x42a2c'], '0x42718': ['0x428c0'], '0x42794': ['0x428a8', '0x42718'], '0x427d8': ['0x42918', '0x422f8'], '0x42808': ['0x427d8', '0x423dc'], '0x42860': ['0x42870'], '0x42870': ['0x42808', '0x42a48'], '0x428a8': ['0x427d8'], '0x428c0': ['0x4266c'], '0x428e4': ['0x42958', '0x42808'], '0x42918': ['0x429e8'], '0x42930': ['0x42794'], '0x42958': ['0x424b0'], '0x4299c': ['0x425b8'], '0x429bc': ['0x4299c'], '0x429d8': ['0x42a48'], '0x429e8': ['0x42518'], '0x42a04': ['0x42860'], '0x42a1c': ['0x429bc'], '0x42a2c': ['0x4262c', '0x429d8'], '0x42ab0': []}

patch_branch(patch_list)


# func_ea =0x41D08
# real_blocks = [269576, 269728, 269844, 269936, 270092, 270180, 270252, 270348, 270424, 270516, 270588, 270636, 270652, 270676, 270768, 270788, 270808, 270832, 270856, 270876, 270908, 272968, 273000, 273024, 273040, 270936, 271096, 271208, 271324, 271444, 271536, 271640, 271728, 271800, 271916, 271980, 272072, 272152, 272276, 272344, 272392, 272480, 272496, 272552, 272576, 272612, 272664, 272688, 272728, 272796, 272828, 272856, 272872, 272900, 272924, 272940, 273072]
# patch_useless_blocks(func_ea,real_blocks)
# ida_funcs.reanalyze_function(ida_funcs.get_func(func_ea))#刷新函数控制流图
# print("控制流图已刷新")