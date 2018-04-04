require './lib/repository'

class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,
         :omniauthable, omniauth_providers: [:google_oauth2]
  include ActiveModel::Validations

  belongs_to :craftsman
  before_create :associate_craftsman

  def associate_craftsman
    craftsman = Craftsman.create(name: self.email, employment_id: 1)
    craftsman.save
    self.craftsman_id = craftsman.employment_id if craftsman
    self.save
  end

  def self.from_omniauth(access_token)
    data = access_token.info
    user = User.where(email: data['email']).first

    unless user
      user = User.create( email: data['email'],
         password: Devise.friendly_token[0,20]
      )
    end

    user
  end

end
