DOCUMENTATION = """
callback: secret_filter
short_description: Masks secrets in task output
version_added: "2.10"
description:
    - This Ansible callback plugin masks secrets in the standard output and
      error of each task result. It searches for secret patterns and replaces
      the corresponding values with asterisks.
    - If other callback plugins are loaded, this plugin chains the output
      through them to ensure that any modifications made by other plugins are
      applied to the masked output.
options:
    secret_patterns:
        description:
            - A list of secret patterns to be masked in task output. Each pattern
              should be a regular expression that matches the secret values to be
              masked. By default, the plugin searches for "password", "secret",
              and "token".
        type: list
        default: ['password', 'secret', 'token']
notes:
    - To use this plugin, place it in a directory called `callback_plugins` in your
      Ansible project, and add the following line to your `ansible.cfg` file:
          callback_plugins = ./callback_plugins
"""

EXAMPLES = """
# Use the secret_filter callback plugin to mask secrets in task output
ansible-playbook playbook.yml -e "ansible_callback_plugins=./callback_plugins" -e "ansible_facts_enabled=false" -e "secret_patterns=['password', 'secret', 'token']"
"""

import re

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_NAME = "secret_filter"

    def __init__(self):
        super().__init__()
        self.secret_patterns = self.get_option("secret_patterns")
        self.other_callbacks = []

    def _try_add_callback(self, callback_class):
        try:
            callback_instance = callback_class()
            if hasattr(callback_instance, "v2_runner_on_ok"):
                self.other_callbacks.append(callback_instance)
        except:
            pass

    def v2_playbook_on_start(self, playbook):
        for callback_class in self._plugin_loader.all():
            self._try_add_callback(callback_class)

    def v2_playbook_on_play_start(self, play):
        for callback_class in self._plugin_loader.all():
            self._try_add_callback(callback_class)

    def v2_runner_on_ok(self, result, **kwargs):
        masked_stdout = self.mask_secrets(result.stdout)
        masked_stderr = self.mask_secrets(result.stderr)
        result._result["stdout"] = masked_stdout
        result._result["stderr"] = masked_stderr

        for callback in self.other_callbacks:
            callback.v2_runner_on_ok(result, **kwargs)

    def mask_secrets(self, output):
        for pattern in self.secret_patterns:
            regex = r"({0})([\s]*=[\s]*)([^\s]+)".format(pattern)
            output = re.sub(regex, r"\1\2********", output)
        return output
