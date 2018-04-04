class AnalyticsController < ApplicationController
  include AnalyticsHelper

  def index
    if params[:falloff]
      @falloff = params[:falloff].to_i
    else
      @falloff = 60
    end
  end
end
