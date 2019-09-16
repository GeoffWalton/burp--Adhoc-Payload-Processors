require 'java'
java_import 'burp.IExtensionHelpers'

java_import 'javax.swing.JOptionPane'
java_import 'burp.ITab'
java_import 'javax.swing.JPanel'
class AbstractBrupExtensionUI < JPanel
  include ITab

  def initialize(extension)
    @extension = extension
    super()
    self.setLayout nil
  end

  def extensionName
    @extension.extensionName
  end

  alias_method :getTabCaption, :extensionName

  def getUiComponent
    self
  end
end

java_import('java.awt.Insets')
class AbstractBurpUIElement
  def initialize(parent, obj, positionX, positionY, width, height)
    @swingElement =obj
    setPosition parent, positionX, positionY, width, height
    parent.add @swingElement
  end

  def method_missing(method, *args, &block)
    @swingElement.send(method, *args)
  end

  private
  def setPosition(parent, x,y,width,height)
    insets = parent.getInsets
    size = @swingElement.getPreferredSize()
    w = (width > size.width) ? width : size.width
    h = (height > size.height) ? height : size.height
    @swingElement.setBounds(x + insets.left, y + insets.top, w, h)
  end
end

java_import 'javax.swing.JLabel'
class BLabel < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, align= :left)
    case align
    when :left
      a = 2
    when :right
      a = 4
    when :center
      a = 0
    else
      a = 2 #align left
    end
    super parent, JLabel.new(caption, a),positionX, positionY, width, height
  end
end


java_import 'javax.swing.JButton'
class BButton < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, &onClick)
    super parent, JButton.new(caption), positionX, positionY, width, height
    @swingElement.add_action_listener onClick
  end
end

java_import 'javax.swing.JSeparator'
class BHorizSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width)
    super parent, JSeparator.new(0), positionX, positionY, width, 1
  end
end

class BVertSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width)
    super parent, JSeparator.new(0), positionX, positionY, width, 1
  end
end

java_import 'javax.swing.JCheckBox'
class BCheckBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JCheckBox.new(caption), positionX, positionY, width, height
  end
end

java_import 'javax.swing.JTextField'
class BTextField < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JTextField.new(caption), positionX, positionY, width, height
  end
end

java_import 'javax.swing.JComboBox'
class BComboBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, &evt)
    super parent, JComboBox.new, positionX, positionY, width, height
    @swingElement.add_action_listener evt
  end
end

java_import 'javax.swing.JTextArea'
java_import 'javax.swing.JScrollPane'
class BTextArea < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height)
    @textArea = JTextArea.new
    super parent, JScrollPane.new(@textArea), positionX, positionY, width, height
  end

  def setText(text)
    @textArea.setText text
  end

  def getText
    @textArea.getText
  end
end

java_import 'burp.ITextEditor'
class BTextEditor < AbstractBurpUIElement
  def initialize(parent, callbacks, positionX, positionY, width, height)
    @textArea = callbacks.createTextEditor
    super parent, JScrollPane.new(@textArea.getComponent), positionX, positionY, width, height
  end

  def setText(text)
    @textArea.setText text.bytes
  end

  def getText
    @textArea.getText.map {|b| b.chr}.join
  end
end

#########################################################################################
#Begin Burp Extension
#########################################################################################

java_import 'burp.IIntruderPayloadProcessor'
require 'base64'
class PayloadProcessorFactory
  SETTINGKEY = 'AdHocExtState'
  attr_reader :extensionName
  attr_accessor :callbacks

  class AbstractPayloadProcessor
    include IIntruderPayloadProcessor

    attr_accessor :originalText

    def initialize(processorName, helpers)
      @processorName = processorName
      @helpers = helpers
    end

    def getProcessorName
      @processorName
    end

    def processPayload(bCurrentPayload, bOriginalPayload, bBaseValue)
      currentPayload = @helpers.bytesToString(bCurrentPayload)
      originalPayload = @helpers.bytesToString(bOriginalPayload)
      baseValue = @helpers.bytesToString(bBaseValue)
      @helpers.stringToBytes(userProcessPayload(currentPayload, originalPayload, baseValue))
    rescue => e
      puts e.message + ':' + 'for ' + currentPayload + ' / ' + originalPayload + ' / ' + baseValue
    end

    def userProcessPayload(currentPayload, originalPayload, baseValue)
      "" #emtpy string
    end
  end

  def initialize(name)
    @extensionName = name
  end

  def getProcessors
    #Return an array with processor names
    processors = @callbacks.getIntruderPayloadProcessors
    processors.map {|p| p.getProcessorName}
  end

  def getProcessorText(name)
    processors = @callbacks.getIntruderPayloadProcessors
    processors.each {|p| return p.originalText if p.getProcessorName == name}
    ''
  end

  def saveExtensionState
    processors = @callbacks.getIntruderPayloadProcessors
    items = processors.map {|p| [p.getProcessorName, p.originalText]}.to_h
    @callbacks.saveExtensionSetting(SETTINGKEY, Base64.strict_encode64(Marshal.dump(items)))
  end

  def loadExtensionState
    stored = @callbacks.loadExtensionSetting(SETTINGKEY)
    return if stored.nil?
    items = Marshal.load Base64.strict_decode64(stored)
    items.each {|key,value| create(key, value)}
  end

  def destroy(processorName)
    processors = @callbacks.getIntruderPayloadProcessors
    processors.each do |processor|
      if processor.getProcessorName() == processorName
      @callbacks.removeIntruderPayloadProcessor(processor)
      processor = nil
      end
    end
  rescue => e
    puts "Failed to remove payload Processor: #{e.message}"
  end

  def create(name, body)
    anon = klass(name, body).new(name, @callbacks.getHelpers)
    anon.originalText = body
    callbacks.registerIntruderPayloadProcessor anon
  rescue => e
    puts "Unable to create payload processor #{name}: #{e.message}"
  end

  def klass(name, body)
    eval "Class.new(AbstractPayloadProcessor) do\n#{body}\nend"
  end
end

class ExtensionUI < AbstractBrupExtensionUI

  SAMPLEBODY = <<"HERE"
#This method is invoked each time the payload processor is applied 
#to an intruder payload.
#
#(string) currentPayload, The value of payload to be processed
#(string) originalPayload, the value of the original payload prior to
#     processing by any already-applied processing rules.
#(string) baseValue the base value of the payload position

def userProcessPayload(currentPayload, originalPayload, baseValue)
  "Sample Payload"
end
HERE

  def buildUI(callbacks)
    BHorizSeparator.new self, 0, 7, 250
    BLabel.new self, 250, 2, 300, 0, 'Payload Processor', :center
    BHorizSeparator.new self, 550, 17, 250
    BLabel.new self,2, 22, 0,0,  'Define the body of the ruby function userProcessPayload below.  The value this function yields will be provided to intruder.'
    BLabel.new self,2, 41, 0,0,  'You may define additional functions or require external files as well.'
    @txtArea = BTextEditor.new( self, callbacks, 2, 53,800,600)
    @txtArea.setText(SAMPLEBODY)
    BLabel.new self, 2,687, 0,0, 'Name for payload processor:'
    @txtName = BTextField.new(self, 160, 685, 450, 12, "NewPayloadProcessor#{rand(5000).to_s}")
    BButton.new( self, 635, 685, 0,0, 'Create Payload Processor') { |evt| createOnClick }
    @cmbProcs = BComboBox.new(self, 2, 715, 450, 0) { |evt| onCmbChange }
    @cmbChanges = true
    updateRemoveList
    BButton.new(self, 462, 715,0,0, 'Remove Processor') {|evt| removeOnClick }
    BButton.new(self,635,715,0,0, 'Restore Template') {|evt| templateOnClick }
    BButton.new(self, 2, 738, 0, 0, 'Save Extension State') {|evt| saveOnClick }
  end

  def saveOnClick
    JOptionPane.showMessageDialog(self, "External files and other resources, 'requires' etc are not saved!\nYou will need to ensure these are present for processors that depend on them.")
    @extension.saveExtensionState
  end

  def updateRemoveList
    @cmbChanges = false
    @cmbProcs.removeAllItems
    @extension.getProcessors.each {|p| @cmbProcs.addItem(p) }
    @cmbChanges = true
  end

  def onCmbChange
    if  @cmbChanges == true
      @txtArea.setText(@extension.getProcessorText(@cmbProcs.getSelectedItem))
    end
  end

  def createOnClick
    if @extension.getProcessorText(@txtName.getText) == ''
      @extension.create(@txtName.getText, @txtArea.getText)
      @txtName.setText "NewPayloadProcessor#{rand(5000).to_s}"
    else
      JOptionPane.showMessageDialog(self, 'Name Conflict Please Choose another name.')
    end
    updateRemoveList
  end

  def templateOnClick
    @txtArea.setText(SAMPLEBODY)
  end

  def removeOnClick
    @extension.destroy(@cmbProcs.getSelectedItem)
    updateRemoveList
  end

end


java_import 'burp.IBurpExtender'
class BurpExtender
  include IBurpExtender
  ExtensionName = 'Adhoc Payload Processing'

  def initialize
    @payloadprocessorfactory = PayloadProcessorFactory.new ExtensionName
    @extensionInterface = ExtensionUI.new @payloadprocessorfactory
  end

  def registerExtenderCallbacks(callbacks)
    callbacks.setExtensionName ExtensionName
    callbacks.addSuiteTab @extensionInterface
    @payloadprocessorfactory.callbacks = callbacks
    @payloadprocessorfactory.loadExtensionState
    @extensionInterface.buildUI(callbacks)
  end

end
