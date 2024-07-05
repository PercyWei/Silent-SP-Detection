# This code is copied from https://github.com/nus-apr/auto-code-rover
# Original file: app/model/register.py

from app.model import common, gpt


def register_all_models() -> None:
    """
    Register all models. This is called in main.
    """
    common.register_model(gpt.Gpt4o_20240513())
    common.register_model(gpt.Gpt4_Turbo20240409())
    common.register_model(gpt.Gpt4_0125Preview())
    common.register_model(gpt.Gpt4_1106Preview())
    common.register_model(gpt.Gpt35_Turbo0125())
    common.register_model(gpt.Gpt35_Turbo1106())
    common.register_model(gpt.Gpt35_Turbo16k_0613())
    common.register_model(gpt.Gpt35_Turbo0613())
    common.register_model(gpt.Gpt4_0613())

    # register default model as selected
    common.SELECTED_MODEL = gpt.Gpt35_Turbo0125()
