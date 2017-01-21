from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Script: enumerate classes',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Enumerate available classes',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    for(var className in ObjC.classes) {
        if(ObjC.classes.hasOwnProperty(className)) {
            send(JSON.stringify({class:className.toString()}));
        }
    }
} else {
    console.log("Objective-C Runtime is not available!");
}
    '''

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        FridaScript.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("frida_script_enum_classes.txt", self)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        hook = self.JS
        self.run_payload(hook)

    def module_post(self):
        temp = [key["class"] for key in self.results]
        self.results = temp
        self.print_cmd_output()