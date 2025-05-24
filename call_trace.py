# -*- coding:utf-8 -*-
import os
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK
from idaapi import get_imagebase
import idaapi
import ida_nalt
import idautils
import idc
import random
from functools import reduce

template_js = '''
var func_addr = [[func_addr]];
var func_name = [[func_name]];
var so_name = "[so_name]";

var callStacks = {};
function getCallStack(tid) {
    if (!callStacks[tid]) {
        callStacks[tid] = [];
    }
    return callStacks[tid];
}

var SCRIPT_START_TIME = Date.now();

function logCallEntry(funcName, tid) {
    var callStack = getCallStack(tid);
    var depth = callStack.length;
    var indent = "  ".repeat(depth);
    var timestamp = Date.now() - SCRIPT_START_TIME;
    console.log(`${indent}[${timestamp} ms] [TID:${tid}] ENTER: ${funcName}`);
}

function logCallExit(funcName, tid) {
    var callStack = getCallStack(tid);
    var depth = callStack.length;
    var indent = "  ".repeat(depth);
    var timestamp = Date.now() - SCRIPT_START_TIME;
    console.log(`${indent}[${timestamp} ms] [TID:${tid}] EXIT: ${funcName}`);
}

function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                if (path.indexOf(so_name) >= 0) {
                    this.is_can_hook = true;
                }
            }
        },
        onLeave: function (retval) {
            if (this.is_can_hook) {
                trace_so();
            }
        }
    });
}

function trace_so() {
    var module = Process.getModuleByName(so_name);
    if (!module) {
        console.log("Module not found: " + so_name);
        return;
    }
    var pid = Process.getCurrentThreadId();
    console.log("start Stalker on thread " + pid);
    Stalker.follow(pid, {
        events: {
            call: false,
            ret: false,
            exec: false,
            block: false,
            compile: true // 需要compile事件以获取指令
        },
        onReceive: function(events) {
            // 未使用
        },
        transform: function (iterator) {
            var instruction = iterator.next();
            do {
                var tid = Process.getCurrentThreadId();
                var callStack = getCallStack(tid);
                var offset = instruction.address.sub(module.base).toInt32();
                var funcIndex = func_addr.indexOf(offset);
                if (funcIndex !== -1) {
                    var funcName = func_name[funcIndex];
                    logCallEntry(funcName, tid);
                    callStack.push(funcName);
                } else if (instruction.mnemonic === 'ret' && callStack.length > 0) {
                    var funcName = callStack.pop();
                    logCallExit(funcName, tid);
                }
                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        }
    });
    console.log("Stalker started!");
}

setImmediate(hook_dlopen, 0);
'''

class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)
        if form_type == idaapi.BWN_FUNCS or form_type == idaapi.BWN_PSEUDOCODE or form_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, "stalkerTraceSo:genJsScript", None)

class GenerateFridaHookScript(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if ctx.widget_type == idaapi.BWN_FUNCS:
            selected = [idaapi.getn_func(idx).start_ea for idx in ctx.chooser_selection]
        else:
            selected = idautils.Functions()
        generate_js_script(selected)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def generate_hook_code(template_js, func_addr, func_name, so_name):
    replacements = {
        "[func_addr]": ', '.join(func_addr),
        "[func_name]": ', '.join(func_name),
        "[so_name]": "%s" % so_name
    }
    return reduce(lambda acc, item: acc.replace(item[0], item[1]), replacements.items(), template_js)

def generate_js_script(func_list):
    func_addr = []
    func_name = []
    so_base = get_imagebase()
    for func_ea in func_list:
        # thumb mode
        if idc.get_sreg(func_ea, "T"):
            func_addr.append(hex(func_ea + 1 - so_base))
        else:
            func_addr.append(hex(func_ea - so_base))
        func_name.append('"{}"'.format(idc.get_func_name(func_ea)))

    so_path, so_name = os.path.split(ida_nalt.get_input_file_path())
    hook_code = generate_hook_code(template_js, func_addr, func_name, so_name)
    r = [random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(5)]
    script_name = "trace_" + so_name.split(".")[0] + '_' + ''.join(r) + ".js"
    save_path = os.path.join(so_path, script_name)
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(hook_code)

    print("usage:")
    print(f'frida -U -l "{save_path}" -f [package name]')

class stalker_trace_so(plugin_t):
    flags = PLUGIN_PROC
    comment = "stalker trace so"
    help = ""
    wanted_name = "stalker trace so"
    wanted_hotkey = ""

    def init(self):
        print("stalker_trace_so plugin has been loaded.")
        idaapi.register_action(
            idaapi.action_desc_t("stalkerTraceSo:genJsScript", "stalker trace so", GenerateFridaHookScript(), None,
                                 None, 201))
        # Add ui hook
        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        generate_js_script(idautils.Functions())

    def term(self):
        pass

def PLUGIN_ENTRY():
    return stalker_trace_so()