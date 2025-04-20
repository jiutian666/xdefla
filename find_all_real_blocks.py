from collections import deque
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
    return all_real_block,all_child_prologue_addr,all_child_prologue_last_ins_ea

func_ea = 0x41D08
reals = find_all_real_block(func_ea)
